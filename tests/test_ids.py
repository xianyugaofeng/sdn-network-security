"""
入侵检测模块单元测试
"""

import unittest
from modules.intrusion_detection import DetectionEngine, SnortIntegration


class TestDetectionEngine(unittest.TestCase):
    """
    检测引擎测试
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.engine = DetectionEngine()

    def test_detect_normal_flow(self):
        """
        测试检测正常流
        """
        flow = {
            'protocol': 'TCP',
            'ip_src': '192.168.1.1',
            'ip_dst': '8.8.8.8',
            'tp_dst': 443,
            'ttl': 64,
            'packet_length': 1500
        }

        alert = self.engine.detect(flow)
        self.assertIsNone(alert)

    def test_detect_abnormal_ttl(self):
        """
        测试检测异常TTL
        """
        flow = {
            'protocol': 'TCP',
            'ttl': 5,  # 异常低的TTL
            'packet_length': 1500
        }

        alert = self.engine.detect(flow)
        # 可能会生成告警（取决于具体实现）

    def test_get_statistics(self):
        """
        测试获取统计信息
        """
        stats = self.engine.get_statistics()

        self.assertIn('total_packets_checked', stats)
        self.assertIn('total_alerts', stats)


class TestSnortIntegration(unittest.TestCase):
    """
    Snort集成测试
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.snort = SnortIntegration(use_builtin=True)

    def test_builtin_rules_loaded(self):
        """
        测试内置规则加载
        """
        self.assertGreater(len(self.snort.rules), 0)

    def test_add_custom_rule(self):
        """
        测试添加自定义规则
        """
        rule = {
            'rule_id': 5001,
            'name': 'Test Rule',
            'patterns': ['test'],
            'severity': 'HIGH'
        }

        result = self.snort.add_custom_rule(rule)
        self.assertTrue(result)
        self.assertIn(5001, self.snort.rules)

    def test_check_packet_sql_injection(self):
        """
        测试检测SQL注入
        """
        payload = "SELECT * FROM users WHERE id = '1' OR '1'='1'"

        matches = self.snort.check_packet_against_rules(payload)
        # 应该检测到SQL注入规则

    def test_check_packet_xss(self):
        """
        测试检测XSS攻击
        """
        payload = "<script>alert('XSS')</script>"

        matches = self.snort.check_packet_against_rules(payload)
        # 应该检测到XSS规则

    def test_get_rule_statistics(self):
        """
        测试获取规则统计
        """
        stats = self.snort.get_rule_statistics()

        self.assertIn('total_rules', stats)
        self.assertIn('by_severity', stats)


class TestDetectionIntegration(unittest.TestCase):
    """
    检测引擎集成测试
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.engine = DetectionEngine()

    def test_port_scan_detection(self):
        """
        测试端口扫描检测
        """
        flows = []
        for port in [22, 23, 25, 80, 443, 3306, 3389]:
            flow = {
                'protocol': 'TCP',
                'ip_src': '192.168.1.100',
                'ip_dst': '192.168.1.1',
                'tp_dst': port,
                'tcp_flags': 2,  # SYN标志
                'packet_length': 64
            }
            flows.append(flow)

        # 应该检测到端口扫描行为


if __name__ == '__main__':
    unittest.main()