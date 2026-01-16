"""
���火墙规则引擎
提供规则匹配、验证和管理功能
"""

import logging
import re
from typing import Dict, List, Any
from ipaddress import ip_address, ip_network

logger = logging.getLogger(__name__)


class RuleEngine: 
    """
    防火墙规则引擎
    """
    
    # 支持的规则字段
    VALID_FIELDS = {
        'id', 'name', 'action', 'protocol', 'ip_src', 'ip_dst',
        'tp_src', 'tp_dst', 'eth_src', 'eth_dst', 'priority',
        'tcp_flags', 'icmp_type', 'rate_threshold', 'description'
    }
    
    # 有效的动作
    VALID_ACTIONS = {'ALLOW', 'DENY', 'ALERT', 'RATE_LIMIT'}
    
    # 有效的协议
    VALID_PROTOCOLS = {'TCP', 'UDP', 'ICMP', 'ALL', 'GRE', 'ESP'}
    
    def __init__(self):
        """
        初始化规则引擎
        """
        self.rules = []
        self.rule_cache = {}
    
    def validate_rule(self, rule: Dict) -> bool:
        """
        验证规则的有效性
        
        Args:
            rule: 规则字典
        
        Returns:
            True:  规则有效
            False: 规则无效
        """
        # 检查必需字段
        if 'action' not in rule or 'protocol' not in rule: 
            logger.error("Rule missing required fields: action, protocol")
            return False
        
        # 验证action
        if rule['action'] not in self.VALID_ACTIONS:
            logger.error(f"Invalid action: {rule['action']}")
            return False
        
        # 验证protocol
        if rule['protocol'] not in self.VALID_PROTOCOLS: 
            logger.error(f"Invalid protocol: {rule['protocol']}")
            return False
        
        # 验证IP地址（如果存在）
        if 'ip_src' in rule: 
            if not self._validate_ip_or_cidr(rule['ip_src']):
                logger.error(f"Invalid source IP: {rule['ip_src']}")
                return False
        
        if 'ip_dst' in rule:
            if not self._validate_ip_or_cidr(rule['ip_dst']):
                logger.error(f"Invalid destination IP: {rule['ip_dst']}")
                return False
        
        # 验证端口
        if 'tp_src' in rule:
            if not self._validate_port(rule['tp_src']):
                logger. error(f"Invalid source port:  {rule['tp_src']}")
                return False
        
        if 'tp_dst' in rule:
            if not self._validate_port(rule['tp_dst']):
                logger.error(f"Invalid destination port: {rule['tp_dst']}")
                return False
        
        # 验证MAC地址
        if 'eth_src' in rule:
            if not self._validate_mac(rule['eth_src']):
                logger.error(f"Invalid source MAC: {rule['eth_src']}")
                return False
        
        if 'eth_dst' in rule:
            if not self._validate_mac(rule['eth_dst']):
                logger.error(f"Invalid destination MAC: {rule['eth_dst']}")
                return False
        
        # 验证优先级
        if 'priority' in rule:
            if not isinstance(rule['priority'], int) or rule['priority'] < 0 or rule['priority'] > 65535:
                logger.error(f"Invalid priority: {rule['priority']}")
                return False
        
        return True
    
    def _validate_ip_or_cidr(self, ip_str: str) -> bool:
        """
        验证IP地址或CIDR表示法
        
        Args: 
            ip_str: IP地址字符串
        
        Returns:
            True: 有效
        """
        try:
            if '/' in ip_str: 
                # CIDR表示法
                ip_network(ip_str, strict=False)
            else:
                # 单个IP
                ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _validate_port(self, port:  Any) -> bool:
        """
        验证端口号
        
        Args:
            port: 端口号
        
        Returns:
            True:  有效
        """
        try:
            port_num = int(port)
            return 0 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    def _validate_mac(self, mac: str) -> bool:
        """
        验证MAC地址
        
        Args:
            mac: MAC地址字符串
        
        Returns: 
            True: 有效
        """
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, mac))
    
    def match_rule(self, flow_info: Dict, rule: Dict) -> bool:
        """
        检查流是否匹配规则
        
        Args:
            flow_info:  流信息字典
            rule: 规则字典
        
        Returns:
            True: 匹配
            False: 不匹配
        """
        # 检查协议
        if not self._match_protocol(flow_info, rule):
            return False
        
        # 检查源IP
        if not self._match_ip(flow_info. get('ip_src'), rule.get('ip_src')):
            return False
        
        # 检查目标IP
        if not self._match_ip(flow_info.get('ip_dst'), rule.get('ip_dst')):
            return False
        
        # 检查源端口
        if not self._match_port(flow_info. get('tp_src'), rule.get('tp_src')):
            return False
        
        # 检查目标端口
        if not self._match_port(flow_info.get('tp_dst'), rule.get('tp_dst')):
            return False
        
        # 检查源MAC
        if not self._match_mac(flow_info.get('eth_src'), rule.get('eth_src')):
            return False
        
        # 检查目标MAC
        if not self._match_mac(flow_info.get('eth_dst'), rule.get('eth_dst')):
            return False
        
        # 检查TCP标志
        if 'tcp_flags' in rule:
            if not self._match_tcp_flags(flow_info.get('tcp_flags'), rule.get('tcp_flags')):
                return False
        
        # 检查ICMP类型
        if 'icmp_type' in rule:
            if flow_info.get('icmp_type') != rule.get('icmp_type'):
                return False
        
        return True
    
    def _match_protocol(self, flow_info: Dict, rule: Dict) -> bool:
        """
        匹配协议
        """
        rule_protocol = rule.get('protocol', 'ALL')
        if rule_protocol == 'ALL': 
            return True
        
        flow_protocol = flow_info.get('protocol')
        return flow_protocol == rule_protocol
    
    def _match_ip(self, flow_ip: str, rule_ip: str) -> bool:
        """
        匹配IP地址
        """
        if rule_ip is None or flow_ip is None:
            return True
        
        try:
            flow_ip_obj = ip_address(flow_ip)
            
            if '/' in rule_ip:
                # CIDR表示法
                rule_network = ip_network(rule_ip, strict=False)
                return flow_ip_obj in rule_network
            else:
                # 单个IP
                rule_ip_obj = ip_address(rule_ip)
                return flow_ip_obj == rule_ip_obj
        except ValueError:
            return False
    
    def _match_port(self, flow_port: Any, rule_port:  Any) -> bool:
        """
        匹配端口号
        """
        if rule_port is None or flow_port is None:
            return True
        
        try
