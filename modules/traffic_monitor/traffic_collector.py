"""
流量采集与监控模块
实时采集、统计和分析网络流量
"""

import logging
from collections import deque, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List
import json

logger = logging.getLogger(__name__)


class TrafficCollector: 
    """
    流量采集器
    """
    
    def __init__(self, max_flows=10000, window_size=3600):
        """
        初始化流量采集器
        
        Args:
            max_flows: 最大保存流数量
            window_size: 时间窗口大小（秒）
        """
        self.max_flows = max_flows
        self.window_size = window_size
        self. flows = deque(maxlen=max_flows)  # 流队列
        self.flow_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'duration': 0,
            'first_seen': None,
            'last_seen': None
        })
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
    
    def record_flow(self, flow_info:  Dict):
        """
        记录流信息
        
        Args: 
            flow_info: 流信息字典
        """
        try:
            # 添加到流队列
            self.flows.append(flow_info)
            
            # 更新流统计
            flow_key = self._get_flow_key(flow_info)
            stats = self.flow_stats[flow_key]
            stats['packets'] += 1
            stats['bytes'] += flow_info.get('packet_length', 0)
            stats['last_seen'] = flow_info.get('timestamp')
            
            if stats['first_seen'] is None: 
                stats['first_seen'] = flow_info.get('timestamp')
            
            # 统计协议
            protocol = flow_info.get('protocol', 'UNKNOWN')
            self.protocol_stats[protocol] += 1
            
            # 统计端口
            dst_port = flow_info.get('tp_dst')
            if dst_port:
                self.port_stats[dst_port] += 1
            
        except Exception as e:
            logger.error(f"Error recording flow: {e}")
    
    def _get_flow_key(self, flow_info: Dict) -> str:
        """
        生成流的唯一键
        
        Args:
            flow_info: 流信息字典
        
        Returns:
            流唯一键
        """
        src_ip = flow_info.get('ip_src', '*')
        dst_ip = flow_info.get('ip_dst', '*')
        src_port = flow_info.get('tp_src', '*')
        dst_port = flow_info.get('tp_dst', '*')
        protocol = flow_info.get('protocol', '*')
        
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}({protocol})"
    
    def get_recent_flows(self, window:  int = 300) -> List[Dict]:
        """
        获取最近窗口内的流
        
        Args:
            window: 时间窗口大小（秒）
        
        Returns:
            流列表
        """
        now = datetime.now()
        cutoff_time = now - timedelta(seconds=window)
        
        recent_flows = []
        for flow in self.flows:
            try:
                flow_time = datetime.fromisoformat(flow. get('timestamp'))
                if flow_time > cutoff_time:
                    recent_flows.append(flow)
            except Exception as e:
                logger.warning(f"Error parsing timestamp: {e}")
        
        return recent_flows
    
    def get_flow_statistics(self) -> Dict:
        """
        获取流统计信息
        
        Returns: 
            统计信息字典
        """
        return {
            'total_flows':  len(self.flows),
            'total_unique_flows': len(self.flow_stats),
            'protocol_distribution': dict(self.protocol_stats),
            'port_distribution': dict(self.port_stats),
            'timestamp': datetime.now().isoformat()
        }
    
    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """
        获取流量最多的源IP
        
        Args:
            limit: 返回数量限制
        
        Returns: 
            IP流量列表
        """
        src_ip_stats = defaultdict(int)
        
        for flow in self.flows:
            src_ip = flow. get('ip_src')
            if src_ip: 
                src_ip_stats[src_ip] += flow.get('packet_length', 0)
        
        top_talkers = sorted(
            src_ip_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        
        return [
            {'ip': ip, 'bytes': bytes_count}
            for ip, bytes_count in top_talkers
        ]
    
    def get_protocol_distribution(self) -> Dict:
        """
        获取协议分布
        
        Returns: 
            协议分布字典
        """
        return dict(self.protocol_stats)
    
    def export_statistics(self, filename: str = 'traffic_stats.json'):
        """
        导出统计信息到文件
        
        Args: 
            filename: 输出文件名
        """
        try: 
            stats = {
                'timestamp': datetime.now().isoformat(),
                'overview': self.get_flow_statistics(),
                'top_talkers': self.get_top_talkers(),
                'protocol_distribution': self.get_protocol_distribution(),
                'detailed_flows': [
                    {
                        'flow_key': self._get_flow_key(flow),
                        'info': flow
                    }
                    for flow in list(self.flows)[-100:]  # 最近100条流
                ]
            }
            
            with open(filename, 'w') as f:
                json.dump(stats, f, indent=2)
            
            logger.info(f"Statistics exported to {filename}")
        except Exception as e:
            logger.error(f"Error exporting statistics: {e}")