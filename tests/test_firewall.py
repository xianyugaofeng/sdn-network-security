"""
防火墙模块单元测试
"""

import unittest
from modules.firewall import DynamicFirewall, RuleEngine


class TestRuleEngine(unittest.TestCase):
    """
    规则引擎测试
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.rule_engine = RuleEngine()

    def test_validate_ip_address(self):
        """
        测试IP地址验证
        """
        self.assertTrue(self.rule_engine._validate_ip_or_cidr('192.168.1.1'))
        self.assertTrue(self.rule_engine._validate_ip_or_cidr('192.168.0.0/16'))
        self.assertFalse(self.rule_engine._validate_ip_or_cidr('999.999.999.999'))
        self.assertFalse(self.rule_engine._validate_ip_or_cidr('invalid'))

    def test_validate_port(self):
        """
        测试端口验证
        """
        self.assertTrue(self.rule_engine._validate_port(80))
        self.assertTrue(self.rule_engine._validate_port(443))
        self.assertTrue(self.rule_engine._validate_port(65535))
        self.assertFalse(self.rule_engine._validate_port(65536))
        self.assertFalse(self.rule_engine._validate_port(-1))

    def test_validate_mac(self):
        """
        测试MAC地址验证
        """
        self.assertTrue(self.rule_engine._validate_mac('00:11:22:33:44:55'))
        self.assertTrue(self.rule_engine._validate_mac('00-11-22-33-44-55'))
        self.assertFalse(self.rule_engine._validate_mac('00:11:22:33:44'))
        self.assertFalse(self.rule_engine._validate_mac('ZZ:ZZ:ZZ: ZZ:ZZ:ZZ'))

    def test_validate_rule(self):
        """
        测试规则验证
        """
        valid_rule = {
            'action': 'ALLOW',
            'protocol': 'TCP',
            'tp_dst': 80
        }
        self.assertTrue(self.rule_engine.validate_rule(valid_rule))

        invalid_rule = {
            'action': 'INVALID_ACTION',
            'protocol': 'TCP'
        }
        self.assertFalse(self.rule_engine.validate_rule(invalid_rule))

        incomplete_rule = {
            'protocol': 'TCP'
        }
        self.assertFalse(self.rule_engine.validate_rule(incomplete_rule))

    def test_match_rule_protocol(self):
        """
        测试协议匹配
        """
        rule = {'protocol': 'TCP', 'action': 'ALLOW'}
        flow_tcp = {'protocol': 'TCP'}
        flow_udp = {'protocol': 'UDP'}

        self.assertTrue(self.rule_engine.match_rule(flow_tcp, rule))
        self.assertFalse(self.rule_engine.match_rule(flow_udp, rule))

    def test_match_rule_ip(self):
        """
        测试IP匹配
        """
        rule = {
            'protocol': 'TCP',
            'action': 'ALLOW',
            'ip_src': '192.168.0.0/16'
        }

        flow_in_range = {
            'protocol': 'TCP',
            'ip_src': '192.168.1.1'
        }

        flow_out_range = {
            'protocol': 'TCP',
            'ip_src': '10.0.0.1'
        }

        self.assertTrue(self.rule_engine.match_rule(flow_in_range, rule))
        self.assertFalse(self.rule_engine.match_rule(flow_out_range, rule))

    def test_match_rule_port(self):
        """
        测试端口匹配
        """
        rule = {
            'protocol': 'TCP',
            'action': 'ALLOW',
            'tp_dst': 80
        }

        flow_match = {
            'protocol': 'TCP',
            'tp_dst': 80
        }

        flow_no_match = {
            'protocol': 'TCP',
            'tp_dst': 443
        }

        self.assertTrue(self.rule_engine.match_rule(flow_match, rule))
        self.assertFalse(self.rule_engine.match_rule(flow_no_match, rule))


class TestDynamicFirewall(unittest.TestCase):
    """
    动态防火墙测试
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.firewall = DynamicFirewall(None)

    def test_add_rule(self):
        """
        测试添加规则
        """
        rule = {
            'id': 1,
            'action': 'ALLOW',
            'protocol': 'TCP',
            'tp_dst': 80,
            'priority': 50
        }

        result = self.firewall.add_rule(rule)
        self.assertTrue(result)
        self.assertEqual(len(self.firewall.rules), 1)

    def test_delete_rule(self):
        """
        测试删除规则
        """
        rule = {
            'id': 1,
            'action': 'ALLOW',
            'protocol': 'TCP'
        }

        self.firewall.add_rule(rule)
        self.assertEqual(len(self.firewall.rules), 1)

        result = self.firewall.delete_rule(1)
        self.assertTrue(result)
        self.assertEqual(len(self.firewall.rules), 0)

    def test_blacklist_operations(self):
        """
        测试黑名单操作
        """
        ip = '192.168.1.100'

        result = self.firewall.add_to_blacklist(ip)
        self.assertTrue(result)
        self.assertIn(ip, self.firewall.blacklist)

        result = self.firewall.remove_from_blacklist(ip)
        self.assertTrue(result)
        self.assertNotIn(ip, self.firewall.blacklist)

    def test_check_policy_blacklist(self):
        """
        测试黑名单策略检查
        """
        self.firewall.add_to_blacklist('10.0.0.1')

        flow = {
            'ip_src': '10.0.0.1',
            'protocol': 'TCP'
        }

        result = self.firewall.check_policy(flow)
        self.assertFalse(result)

    def test_check_policy_whitelist(self):
        """
        测试白名单策略检查
        """
        self.firewall.whitelist.add('10.0.0.1')

        flow = {
            'ip_src': '10.0.0.1',
            'protocol': 'TCP'
        }

        result = self.firewall.check_policy(flow)
        self.assertTrue(result)

    def test_get_statistics(self):
        """
        测试获取统计信息
        """
        rule = {
            'id': 1,
            'action': 'ALLOW',
            'protocol': 'TCP'
        }
        self.firewall.add_rule(rule)
        self.firewall.add_to_blacklist('10.0.0.1')
        self.firewall.whitelist.add('192.168.1.1')

        stats = self.firewall.get_statistics()

        self.assertEqual(stats['total_rules'], 1)
        self.assertEqual(stats['blacklist_size'], 1)
        self.assertEqual(stats['whitelist_size'], 1)


class TestFirewallIntegration(unittest.TestCase):
    """
    防火墙集成测试
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.firewall = DynamicFirewall(None)

    def test_allow_http(self):
        """
        测试允许HTTP流量
        """
        rule = {
            'id': 1,
            'action': 'ALLOW',
            'protocol': 'TCP',
            'tp_dst': 80,
            'priority': 50
        }
        self.firewall.add_rule(rule)

        flow = {
            'protocol': 'TCP',
            'tp_dst': 80
        }

        result = self.firewall.check_policy(flow)
        self.assertTrue(result)

    def test_deny_ssh(self):
        """
        测试拒绝SSH流量
        """
        rule = {
            'id': 1,
            'action': 'DENY',
            'protocol': 'TCP',
            'tp_dst': 22,
            'priority': 100
        }
        self.firewall.add_rule(rule)

        flow = {
            'protocol': 'TCP',
            'tp_dst': 22
        }

        result = self.firewall.check_policy(flow)
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()