"""
动态防火墙模块
支持实时规则下发、黑白名单、协议过滤等功能
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple
from . rule_engine import RuleEngine

logger = logging.getLogger(__name__)


class DynamicFirewall:
    """
    动态防火墙类
    """
    
    def __init__(self, controller):
        """
        初始化防火墙
        
        Args:
            controller: SDN控制器实例
        """
        self. controller = controller
        self.rule_engine = RuleEngine()
        self.rules = []  # 防火墙规则列表
        self.blacklist = set()  # 黑名单IP
        self.whitelist = set()  # 白名单IP
        self.load_rules_from_file()
    
    def load_rules_from_file(self, config_file='config/rules.json'):
        """
        从配置文件加载规则
        """
        try: 
            with open(config_file, 'r') as f:
                config = json.load(f)
                self.rules = config.get('rules', [])
                self.blacklist = set(config.get('blacklist', []))
                self.whitelist = set(config. get('whitelist', []))
                logger.info(f"Loaded {len(self.rules)} firewall rules")
        except FileNotFoundError: 
            logger.warning(f"Config file {config_file} not found, using empty rules")
            self.rules = []
    
    def check_policy(self, flow_info: Dict) -> bool:
        """
        检查流是否符合防火墙策略
        
        Args: 
            flow_info: 流信息字典
        
        Returns:
            True: 允许该流
            False: 阻止该流
        """
        # 先检查黑名单
        src_ip = flow_info.get('ip_src')
        if src_ip and src_ip in self.blacklist:
            logger.warning(f"Packet from blacklisted IP: {src_ip}")
            return False
        
        # 检查白名单
        if src_ip and src_ip in self.whitelist:
            return True
        
        # 检查防火墙规则
        for rule in self.rules:
            if self.rule_engine.match_rule(flow_info, rule):
                action = rule.get('action', 'DENY')
                if action == 'ALLOW': 
                    return True
                elif action == 'DENY': 
                    return False
        
        # 默认策略：允许
        return True
    
    def add_rule(self, rule: Dict) -> bool:
        """
        添加防火墙规则
        
        Args:
            rule: 规则字典
        
        Returns:
            True: 添加成功
        """
        try:
            if self.rule_engine.validate_rule(rule):
                self.rules.append(rule)
                logger.info(f"Rule added: {rule}")
                return True
            else:
                logger.error(f"Invalid rule: {rule}")
                return False
        except Exception as e:
            logger.error(f"Error adding rule: {e}")
            return False
    
    def delete_rule(self, rule_id: int) -> bool:
        """
        删除防火墙规则
        
        Args: 
            rule_id: 规则ID
        
        Returns: 
            True: 删除成功
        """
        try: 
            self.rules = [r for r in self.rules if r.get('id') != rule_id]
            logger.info(f"Rule {rule_id} deleted")
            return True
        except Exception as e:
            logger.error(f"Error deleting rule: {e}")
            return False
    
    def add_to_blacklist(self, ip:  str) -> bool:
        """
        添加IP到黑名单
        
        Args:
            ip: IP地址
        
        Returns: 
            True: 添加成功
        """
        try:
            self.blacklist.add(ip)
            logger.info(f"IP {ip} added to blacklist")
            return True
        except Exception as e:
            logger. error(f"Error adding to blacklist: {e}")
            return False
    
    def remove_from_blacklist(self, ip: str) -> bool:
        """
        从黑名单移除IP
        
        Args:
            ip: IP地址
        
        Returns: 
            True: 移除成功
        """
        try: 
            self.blacklist.discard(ip)
            logger.info(f"IP {ip} removed from blacklist")
            return True
        except Exception as e: 
            logger.error(f"Error removing from blacklist: {e}")
            return False
    
    def install_base_rules(self, datapath):
        """
        在交换机上安装基础规则
        
        Args:
            datapath:  交换机对象
        """
        logger.info(f"Installing base rules on switch {datapath.id}")
        
        # 安装允许ARP流量的规则
        self._install_arp_rule(datapath)
        
        # 安装ICMP规则（可选，用于诊断）
        self._install_icmp_rule(datapath)
    
    def _install_arp_rule(self, datapath):
        """
        安装ARP规则
        """
        ofproto = datapath.ofproto
        parser = datapath. ofproto_parser
        
        match = parser.OFPMatch(eth_type=0x0806)  # ARP
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        
        self.controller.add_flow(datapath, 50, match, actions)
        logger.debug("ARP rule installed")
    
    def _install_icmp_rule(self, datapath):
        """
        安装ICMP规则
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=1  # ICMP
        )
        actions = [parser.OFPActionOutput(ofproto. OFPP_FLOOD)]
        
        self.controller.add_flow(datapath, 40, match, actions)
        logger.debug("ICMP rule installed")
    
    def get_statistics(self) -> Dict:
        """
        获取防火墙统计信息
        
        Returns:
            统计信息字典
        """
        return {
            'total_rules': len(self.rules),
            'blacklist_size': len(self.blacklist),
            'whitelist_size':  len(self.whitelist),
            'timestamp': datetime.now().isoformat()
        }