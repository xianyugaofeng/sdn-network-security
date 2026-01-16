"""
Snort入侵检测系统集成模块
集成Snort规则库进行实时检测
"""

import logging
import subprocess
import os
import json
from typing import Dict, List, Optional
from datetime import datetime
import threading
import queue

logger = logging.getLogger(__name__)


class SnortIntegration: 
    """
    Snort集成类
    """
    
    # Snort默认配置路径
    DEFAULT_SNORT_PATH = '/usr/sbin/snort'
    DEFAULT_CONF_PATH = '/etc/snort/snort.conf'
    DEFAULT_RULES_PATH = '/etc/snort/rules'
    
    # 预定义的规则集合
    BUILTIN_RULES = {
        'malware_c2': {
            'rule_id': 2001,
            'name': 'Malware C&C Communication',
            'patterns': ['cmd. exe', 'powershell', 'wscript'],
            'severity': 'CRITICAL'
        },
        'exploit_attempt': {
            'rule_id': 2002,
            'name': 'Known Exploit Attempt',
            'patterns': ['/../', '.. \\', 'buffer overflow'],
            'severity': 'HIGH'
        },
        'port_scan': {
            'rule_id': 2003,
            'name': 'Port Scan Detected',
            'patterns': ['nmap', 'masscan', 'zmap'],
            'severity': 'MEDIUM'
        },
        'sql_injection': {
            'rule_id': 2004,
            'name': 'SQL Injection Attempt',
            'patterns': ["' OR '1'='1", 'union select', 'drop table'],
            'severity': 'HIGH'
        },
        'xss_attack': {
            'rule_id': 2005,
            'name': 'XSS Attack',
            'patterns': ['<script', 'javascript:', 'onerror='],
            'severity': 'MEDIUM'
        },
        'ddos_pattern': {
            'rule_id': 2006,
            'name': 'DDoS Pattern Detected',
            'patterns': ['slowhttptest', 'syn flood', 'icmp flood'],
            'severity':  'CRITICAL'
        }
    }
    
    def __init__(self, snort_path: str = None, conf_path: str = None, 
                 rules_path: str = None, use_builtin: bool = True):
        """
        初始化Snort集成
        
        Args:
            snort_path: Snort可执行文件路径
            conf_path: Snort配置文件路径
            rules_path:  Snort规则文件路径
            use_builtin: 是否使用内置规则
        """
        self.snort_path = snort_path or self.DEFAULT_SNORT_PATH
        self.conf_path = conf_path or self.DEFAULT_CONF_PATH
        self.rules_path = rules_path or self.DEFAULT_RULES_PATH
        self.use_builtin = use_builtin
        
        self.rules = {}
        self.alerts = []
        self.process = None
        self.alert_queue = queue.Queue()
        
        if use_builtin:
            self._load_builtin_rules()
        
        logger.info("Snort Integration initialized")
    
    def _load_builtin_rules(self):
        """
        加载内置规则
        """
        self.rules = self.BUILTIN_RULES. copy()
        logger.info(f"Loaded {len(self.rules)} built-in rules")
    
    def add_custom_rule(self, rule: Dict) -> bool:
        """
        添加自定义规则
        
        Args:
            rule: 规则字典
        
        Returns:
            True:  添加成功
        """
        required_fields = {'rule_id', 'name', 'patterns', 'severity'}
        
        if not all(field in rule for field in required_fields):
            logger.error("Custom rule missing required fields")
            return False
        
        rule_id = rule['rule_id']
        if rule_id in self.rules:
            logger.warning(f"Rule {rule_id} already exists, overwriting")
        
        self. rules[rule_id] = rule
        logger.info(f"Custom rule {rule_id} added")
        return True
    
    def check_packet_against_rules(self, payload: str) -> List[Dict]:
        """
        检查数据包内容
        
        Args:
            payload: 数据包有效负载
        
        Returns:
            匹配的规则列表
        """
        matched_rules = []
        payload_lower = payload.lower()
        
        for rule_id, rule in self.rules.items():
            patterns = rule.get('patterns', [])
            
            for pattern in patterns:
                if pattern. lower() in payload_lower:
                    matched_rules.append({
                        'rule_id':  rule_id,
                        'name': rule.get('name'),
                        'severity': rule. get('severity'),
                        'matched_pattern': pattern
                    })
                    break  # 只匹配一次
        
        return matched_rules
    
    def start_snort_daemon(self, interface: str = None) -> bool:
        """
        启动Snort守护进程
        
        Args: 
            interface: 网络接口
        
        Returns:
            True: 启动成功
        """
        try:
            if not os.path.exists(self. snort_path):
                logger.error(f"Snort not found at {self.snort_path}")
                return False
            
            # 构建Snort命令
            cmd = [
                self.snort_path,
                '-c', self.conf_path,
                '-l', '/var/log/snort'
            ]
            
            if interface:
                cmd.extend(['-i', interface])
            
            # 启动Snort进程
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess. PIPE,
                stderr=subprocess. PIPE,
                text=True
            )
            
            logger.info("Snort daemon started")
            return True
        except Exception as e:
            logger. error(f"Error starting Snort:  {e}")
            return False
    
    def stop_snort_daemon(self) -> bool:
        """
        停止Snort守护进程
        
        Returns: 
            True: 停止成功
        """
        try:
            if self.process:
                self.process.terminate()
                self.process.wait(timeout=5)
                logger.info("Snort daemon stopped")
                return True
            return False
        except Exception as e: 
            logger.error(f"Error stopping Snort: {e}")
            return False
    
    def parse_snort_alerts(self, log_file: str = '/var/log/snort/alert') -> List[Dict]:
        """
        解析Snort告警日志
        
        Args: 
            log_file: 告警日志文件
        
        Returns:
            解析后的告警列表
        """
        alerts = []
        
        try:
            if not os.path.exists(log_file):
                logger.warning(f"Alert log not found:  {log_file}")
                return alerts
            
            with open(log_file, 'r') as f:
                content = f.read()
            
            # 简单的告警解析（实际应使用更复杂的解析）
            lines = content.split('\n')
            
            for line in lines:
                if line.strip():
                    alert = self._parse_alert_line(line)
                    if alert:
                        alerts.append(alert)
            
            logger.info(f"Parsed {len(alerts)} alerts from log")
            return alerts
        except Exception as e:
            logger. error(f"Error parsing alerts:  {e}")
            return alerts
    
    def _parse_alert_line(self, line: str) -> Optional[Dict]:
        """
        解析单条告警行
        
        Args:
            line: 告警行
        
        Returns: 
            解析后的告警字典
        """
        try:
            # 简化的解析逻辑
            parts = line.split()
            
            if len(parts) < 5:
                return None
            
            return {
                'timestamp': datetime.now().isoformat(),
                'source_ip': parts[0] if len(parts) > 0 else None,
                'dest_ip': parts[1] if len(parts) > 1 else None,
                'message': ' '.join(parts[4:]) if len(parts) > 4 else None,
                'severity': 'MEDIUM'
            }
        except Exception as e:
            logger.debug(f"Error parsing alert line:  {e}")
            return None
    
    def generate_snort_rule(self, rule_dict: Dict) -> str:
        """
        生成Snort规则格式字符串
        
        Args: 
            rule_dict: 规则字典
        
        Returns:
            Snort规则字符串
        """
        rule_str = f"alert tcp any any -> any any (msg:\"{rule_dict. get('name')}\"; "
        rule_str += f"sid:{rule_dict. get('rule_id')}; "
        
        patterns = rule_dict.get('patterns', [])
        if patterns: 
            content_parts = [f'content:\"{p}\";' for p in patterns]
            rule_str += " ". join(content_parts) + " "
        
        rule_str += f"rev: 1; classtype:unknown; priority:3;)"
        
        return rule_str
    
    def export_rules(self, filename: str = 'snort_rules.rules') -> bool:
        """
        导出规则到文件
        
        Args:
            filename: 输出文件名
        
        Returns:
            True: 导出成功
        """
        try:
            with open(filename, 'w') as f:
                for rule_id, rule in self. rules.items():
                    rule_str = self.generate_snort_rule(rule)
                    f.write(rule_str + '\n')
            
            logger.info(f"Rules exported to {filename}")
            return True
        except Exception as e: 
            logger.error(f"Error exporting rules: {e}")
            return False
    
    def get_rule_statistics(self) -> Dict:
        """
        获取规则统计信息
        
        Returns:
            统计字典
        """
        severity_count = {}
        for rule in self.rules.values():
            severity = rule.get('severity', 'UNKNOWN')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        return {
            'total_rules': len(self.rules),
            'by_severity': severity_count,
            'timestamp': datetime.now().isoformat()
        }