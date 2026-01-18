"""
SDN网络安全控制器 - 基于Ryu框架
支持动态防火墙、流量监控、入侵检测等功能
"""

import sys
import os

# Add project root to Python path to enable imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib import hub
import logging
import json
from datetime import datetime
from modules.firewall.dynamic_firewall import DynamicFirewall
from modules.traffic_monitor.traffic_collector import TrafficCollector
from modules.intrusion_detection.detection_engine import DetectionEngine
from modules.anomaly_detection.kmeans_analyzer import KMeansAnalyzer
from utils.logger import setup_logger
from utils.db_helper import DatabaseHelper

# 日志配置
logger = setup_logger('SDNController', 'logs/sdn_controller.log')


class SDNSecurityController(app_manager.RyuApp):
    """
    SDN网络安全控制器主类
    """
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SDNSecurityController, self).__init__(*args, **kwargs)
        
        # 初始化各个安全模块
        self.firewall = DynamicFirewall(self)
        self.traffic_collector = TrafficCollector()
        self.ids_engine = DetectionEngine()
        self.anomaly_detector = KMeansAnalyzer()
        self.db = DatabaseHelper()
        
        # 数据结构
        self.datapaths = {}  # 交换机字典
        self.flow_stats = {}  # 流统计数据
        self.packets_data = {}  # 数据包数据
        
        # 启动定时任务
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.anomaly_thread = hub.spawn(self._anomaly_detection_loop)
        
        logger.info("SDN Security Controller started successfully")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        交换机连接事件处理
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.datapaths[datapath.id] = datapath
        logger.info(f"Switch {datapath.id} connected")
        
        # 安装table miss流表项
        self._install_table_miss(datapath)
        
        # 应用防火墙初始规则
        self.firewall.install_base_rules(datapath)
    
    def _install_table_miss(self, datapath):
        """
        安装table miss流表项
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # 创建match条件（匹配所有包）
        match = parser.OFPMatch()
        
        # 创建action：发送到控制器
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow(datapath, 0, match, actions)
        logger.debug(f"Table miss flow installed on switch {datapath.id}")
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        数据包进入事件处理
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        # 解析数据包
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.dst == '00:00:00:00:00:00':
            return
        
        # 提取流信息
        flow_info = self._extract_flow_info(pkt, in_port, datapath.id)
        
        # 防火墙检查
        if not self.firewall.check_policy(flow_info):
            logger.warning(f"Packet blocked by firewall:  {flow_info}")
            return  # 丢弃数据包
        
        # 流量监控
        self.traffic_collector.record_flow(flow_info)
        
        # 入侵检测
        alert = self.ids_engine.detect(flow_info)
        if alert:
            logger.alert(f"Intrusion detected:  {alert}")
            self._handle_intrusion(datapath, flow_info)
        
        # 学习MAC地址并转发
        self._handle_forwarding(datapath, msg, flow_info)
    
    def _extract_flow_info(self, pkt, in_port, datapath_id):
        """
        从数据包提取流信息
        """
        flow_info = {
            'timestamp': datetime.now().isoformat(),
            'datapath_id': datapath_id,
            'in_port':  in_port,
            'eth_src': None,
            'eth_dst':  None,
            'ip_src': None,
            'ip_dst': None,
            'ip_proto': None,
            'tp_src': None,
            'tp_dst': None,
            'packet_length': len(pkt),
        }
        
        # 以太网层
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth:
            flow_info['eth_src'] = eth.src
            flow_info['eth_dst'] = eth.dst
            flow_info['eth_type'] = eth.ethertype
        
        # IP层
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            flow_info['ip_src'] = ipv4_pkt.src
            flow_info['ip_dst'] = ipv4_pkt.dst
            flow_info['ip_proto'] = ipv4_pkt.proto
            flow_info['ttl'] = ipv4_pkt.ttl
        
        # 传输层
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            flow_info['tp_src'] = tcp_pkt.src_port
            flow_info['tp_dst'] = tcp_pkt.dst_port
            flow_info['protocol'] = 'TCP'
            flow_info['tcp_flags'] = tcp_pkt.flags
        
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            flow_info['tp_src'] = udp_pkt.src_port
            flow_info['tp_dst'] = udp_pkt.dst_port
            flow_info['protocol'] = 'UDP'
        
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if icmp_pkt:
            flow_info['protocol'] = 'ICMP'
            flow_info['icmp_type'] = icmp_pkt.type
            flow_info['icmp_code'] = icmp_pkt.code
        
        return flow_info
    
    def _handle_forwarding(self, datapath, msg, flow_info):
        """
        处理数据包转发
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # 简化的转发逻辑（实际应用中需更复杂的MAC表管理）
        out_port = ofproto.OFPP_FLOOD
        
        # 创建match条件
        match = parser.OFPMatch(
            eth_src=flow_info['eth_src'],
            eth_dst=flow_info['eth_dst']
        )
        
        # 创建action
        actions = [parser.OFPActionOutput(out_port)]
        
        # 安装流表
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, 1, match, actions)
        
        # 转发数据包
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
    
    def _handle_intrusion(self, datapath, flow_info):
        """
        处理入侵事件
        """
        logger.critical(f"Intrusion event:  {flow_info}")
        
        # 创建阻断规则
        block_match = datapath.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=flow_info.get('ip_src'),
            ipv4_dst=flow_info.get('ip_dst')
        )
        
        # 安装高优先级的阻断流表
        self.add_flow(datapath, 100, block_match, [])  # 空action表示丢弃
        
        # 记录到数据库
        self.db.insert_intrusion_alert({
            'timestamp': flow_info['timestamp'],
            'source_ip': flow_info.get('ip_src'),
            'dest_ip': flow_info.get('ip_dst'),
            'protocol': flow_info.get('protocol'),
            'severity': 'HIGH'
        })
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        安装流表项
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst
            )
        
        datapath.send_msg(mod)
    
    def _monitor_loop(self):
        """
        流量监控定时任务
        """
        while True:
            for datapath in self.datapaths.values():
                self._request_stats(datapath)
            
            hub.sleep(10)  # 每10秒收集一次统计信息
    
    def _request_stats(self, datapath):
        """
        请求交换机统计信息
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # 请求流表统计
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        
        # 请求端口统计
        req = parser.OFPPortStatsRequest(datapath, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        流表统计回复处理
        """
        body = ev.msg.body
        datapath_id = ev.msg.datapath.id
        
        self.flow_stats[datapath_id] = body
        
        # 输出统计信息
        for stat in body: 
            logger.debug(f"Flow {stat.match} - Packets: {stat.packet_count}, Bytes: {stat.byte_count}")
    
    def _anomaly_detection_loop(self):
        """
        异常检测定时任务
        """
        while True: 
            # 收集最近的流量数据
            recent_flows = self.traffic_collector.get_recent_flows(window=300)  # 5分钟窗口
            
            if len(recent_flows) > 10:
                # 执行异常检测
                anomalies = self.anomaly_detector.detect(recent_flows)
                
                if anomalies:
                    logger.warning(f"Anomalies detected: {anomalies}")
                    self.db.insert_anomaly_alert(anomalies)
            
            hub.sleep(60)  # 每分钟检测一次


def main():
    """
    主程序入口
    """
    app_manager.run_apps([SDNSecurityController])


if __name__ == '__main__':
    main()