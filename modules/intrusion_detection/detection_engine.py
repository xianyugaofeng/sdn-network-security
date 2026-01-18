"""
入侵检测引擎
集成Snort规则库，实现多层检测机制
"""

import logging
import re
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    入侵检测引擎
    """
    
    # 常见攻击特征库
    ATTACK_PATTERNS = {
        'port_scan': {
            'description': '端口扫描检测',
            'check':  lambda flow: flow.get('protocol') == 'TCP' and flow.get('tcp_flags') == 2
        },
        'syn_flood': {
            'description': 'SYN泛洪攻击检测',
            'check': lambda flow: flow.get('protocol') == 'TCP' and flow. get('tcp_flags') == 2
        },
        'udp_flood': {
            'description': 'UDP泛洪攻击检测',
            'check': lambda flow: flow.get('protocol') == 'UDP'
        },
        'icmp_sweep': {
            'description': 'ICMP扫描检测',
            'check': lambda flow: flow.get('protocol') == 'ICMP' and flow.get('icmp_type') == 8
        },
        'sql_injection': {
            'description': 'SQL注入检测',
            'check': lambda flow: 'sql' in str(flow.get('payload', '')).lower()
        },
        'xss_attack': {
            'description': 'XSS攻击检测',
            'check': lambda flow: '<script' in str(flow.get('payload', '')).lower()
        }
    }
    
    # Snort基础规则示例
    SNORT_RULES = [
        {
            'sid': 1001,
            'msg': 'Suspicious port 22 activity',
            'protocol': 'TCP',
            'dst_port': 22,
            'content': '',
            'flow':  'to_server,established'
        },
        {
            'sid': 1002,
            'msg': 'Excessive DNS queries',
            'protocol': 'UDP',
            'dst_port': 53,
            'threshold': 50  # 每分钟超过50个DNS查询
        },
        {
            'sid': 1003,
            'msg': 'Known malware C&C communication',
            'protocol': 'TCP',
            'content': ['cmd. exe', 'powershell'],
            'severity': 'CRITICAL'
        }
    ]
    
    def __init__(self):
        """
        初始化检测引擎
        """
        self.alerts = []
        self.statistics = {
            'total_packets_checked': 0,
            'total_alerts': 0,
            'alerts_by_type': {}
        }
        self.session_cache = {}  # 会话缓存
    
    def detect(self, flow_info: Dict) -> Optional[Dict]:
        """
        检测单个流
        
        Args: 
            flow_info: 流信息字典
        
        Returns:
            告警信息字典或None
        """
        self.statistics['total_packets_checked'] += 1
        
        # 1. 检查协议异常
        protocol_alert = self._check_protocol_anomaly(flow_info)
        if protocol_alert:
            return self._create_alert(protocol_alert, flow_info)
        
        # 2. 检查已知攻击特征
        pattern_alert = self._check_attack_patterns(flow_info)
        if pattern_alert:
            return self._create_alert(pattern_alert, flow_info)
        
        # 3. 检查Snort规则
        snort_alert = self._check_snort_rules(flow_info)
        if snort_alert: 
            return self._create_alert(snort_alert, flow_info)
        
        # 4. 检查会话行为异常
        session_alert = self._check_session_anomaly(flow_info)
        if session_alert:
            return self._create_alert(session_alert, flow_info)
        
        return None
    
    def _check_protocol_anomaly(self, flow_info: Dict) -> Optional[str]:
        """
        检查协议异常
        """
        protocol = flow_info.get('protocol')
        ip_proto = flow_info.get('ip_proto')
        
        # 检查不合理的TTL值
        ttl = flow_info.get('ttl')
        if ttl and ttl < 10:
            return f"Unusual TTL value: {ttl}"
        
        # 检查TCP标志异常
        if protocol == 'TCP':
            tcp_flags = flow_info.get('tcp_flags', 0)
            # SYN-ACK without SYN (异常)
            if tcp_flags == 18 and tcp_flags == 20:
                return "Suspicious TCP flags combination"
        
        return None
    
    def _check_attack_patterns(self, flow_info: Dict) -> Optional[str]:
        """
        检查已知攻击特征
        """
        for attack_type, pattern_info in self.ATTACK_PATTERNS.items():
            try:
                if pattern_info['check'](flow_info):
                    logger.warning(f"Attack pattern detected: {attack_type}")
                    return f"{attack_type}:  {pattern_info['description']}"
            except Exception as e: 
                logger.debug(f"Error checking pattern {attack_type}: {e}")
        
        return None
    
    def _check_snort_rules(self, flow_info: Dict) -> Optional[Dict]:
        """
        检查Snort规则
        """
        for rule in self. SNORT_RULES:
            # 协议匹配
            if rule.get('protocol') != flow_info.get('protocol'):
                continue
            
            # 目的端口匹配
            dst_port = rule.get('dst_port')
            if dst_port and dst_port != flow_info.get('tp_dst'):
                continue
            
            # 内容匹配
            content = rule.get('content')
            if content and not self._check_content(flow_info, content):
                continue
            
            logger.warning(f"Snort rule matched: {rule.get('msg')}")
            return {
                'rule_id': rule.get('sid'),
                'message': rule.get('msg'),
                'severity': rule.get('severity', 'MEDIUM')
            }
        
        return None
    
    def _check_session_anomaly(self, flow_info: Dict) -> Optional[str]:
        """
        检查会话异常
        """
        src_ip = flow_info.get('ip_src')
        
        if not src_ip:
            return None
        
        # 初始化或更新会话信息
        if src_ip not in self.session_cache:
            self.session_cache[src_ip] = {
                'packet_count': 0,
                'bytes_count': 0,
                'protocols': set(),
                'ports': set(),
                'first_seen': datetime.now()
            }
        
        session = self.session_cache[src_ip]
        session['packet_count'] += 1
        session['bytes_count'] += flow_info.get('packet_length', 0)
        session['protocols'].add(flow_info.get('protocol'))
        
        dst_port = flow_info.get('tp_dst')
        if dst_port:
            session['ports'].add(dst_port)
        
        # 检查异常条件
        if session['packet_count'] > 1000:  # 短时间内发送大量包
            return f"High packet volume from {src_ip}:  {session['packet_count']} packets"
        
        if len(session['ports']) > 100:  # 连接到多个不同端口（端口扫描）
            return f"Port scanning detected from {src_ip}:  {len(session['ports'])} unique ports"
        
        if len(session['protocols']) > 3:  # 使用多个协议（可能的探测）
            return f"Multiple protocols from {src_ip}: {session['protocols']}"
        
        return None
    
    def _check_content(self, flow_info: Dict, content: List) -> bool:
        """
        检查流中是否包含特定内容
        """
        # 简化实现，实际应检查数据包有效负载
        return True
    
    def _create_alert(self, alert_msg, flow_info: Dict) -> Dict:
        """
        创建告警
        
        Args:
            alert_msg: 告警消息（可以是字符串或字典）
            flow_info: 流信息
        """
        # Handle both string and dict alert messages
        if isinstance(alert_msg, dict):
            message = alert_msg.get('message', 'Unknown alert')
            severity = alert_msg.get('severity', 'HIGH')
        else:
            message = str(alert_msg)
            severity = 'HIGH'
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'message': message,
            'source_ip': flow_info.get('ip_src'),
            'dest_ip': flow_info.get('ip_dst'),
            'protocol': flow_info.get('protocol'),
            'dst_port': flow_info.get('tp_dst')
        }
        
        self.alerts.append(alert)
        self.statistics['total_alerts'] += 1
        
        # Extract alert type from message
        if isinstance(message, str):
            alert_type = message.split(': ')[0] if ': ' in message else message.split(':')[0] if ':' in message else 'UNKNOWN'
        else:
            alert_type = 'UNKNOWN'
        
        self.statistics['alerts_by_type'][alert_type] = \
            self.statistics['alerts_by_type'].get(alert_type, 0) + 1
        
        return alert
    
    def get_statistics(self) -> Dict:
        """
        获取检测统计信息
        """
        return self.statistics
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """
        获取最近的告警
        """
        return self.alerts[-limit:]