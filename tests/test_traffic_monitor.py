"""
流量监控模块单元测试
"""

import unittest
from modules.traffic_monitor import TrafficCollector, StatisticsCollector


class TestTrafficCollector(unittest.TestCase):
    """
    流量采集器测试
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.collector = TrafficCollector(max_flows=1000)

    def test_record_flow(self):
        """
        测试记录流
        """
        flow = {
            'ip_src': '192.168.1.1',
            'ip_dst': '192.168.1.2',
            'protocol': 'TCP',
            'tp_src': 12345,
            'tp_dst': 80,
            'packet_length': 1500
        }

        self.collector.record_flow(flow)
        self.assertEqual(len(self.collector.flows), 1)

    def test_get_flow_statistics(self):
        """
        测试获取流统计
        """
        flow = {
            'ip_src': '192.168.1.1',
            'ip_dst': '192.168.1.2',
            'protocol': 'TCP',
            'packet_length': 1500
        }

        self.collector.record_flow(flow)

        stats = self.collector.get_flow_statistics()

        self.assertEqual(stats['total_flows'], 1)
        self.assertEqual(stats['total_unique_flows'], 1)
        self.assertIn('TCP', stats['protocol_distribution'])

    def test_get_top_talkers(self):
        """
        测试获取流量最多的主机
        """
        flows = [
            {
                'ip_src': '192.168.1.1',
                'ip_dst': '192.168.1.2',
                'packet_length': 5000
            },
            {
                'ip_src': '192.168.1.2',
                'ip_dst': '192.168.1.3',
                'packet_length': 3000
            },
            {
                'ip_src': '192.168.1.1',
                'ip_dst': '192.168.1.3',
                'packet_length': 2000
            }
        ]

        for flow in flows:
            self.collector.record_flow(flow)

        top_talkers = self.collector.get_top_talkers(limit=2)

        self.assertEqual(len(top_talkers), 2)
        self.assertEqual(top_talkers[0]['ip'], '192.168.1.1')

    def test_get_protocol_distribution(self):
        """
        测试获取协议分布
        """
        flows = [
            {'protocol': 'TCP', 'packet_length': 1000},
            {'protocol': 'TCP', 'packet_length': 2000},
            {'protocol': 'UDP', 'packet_length': 500},
            {'protocol': 'ICMP', 'packet_length': 100}
        ]

        for flow in flows:
            self.collector.record_flow(flow)

        stats = self.collector.get_flow_statistics()

        self.assertIn('TCP', stats['protocol_distribution'])
        self.assertIn('UDP', stats['protocol_distribution'])
        self.assertIn('ICMP', stats['protocol_distribution'])


class TestStatisticsCollector(unittest.TestCase):
    """
    统计收集器测试
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.stats = StatisticsCollector()

    def test_update_flow_stats(self):
        """
        测试更新流统计
        """
        flow_key = "192.168.1.1:12345->192.168.1.2:80(TCP)"

        self.stats.update_flow_stats(flow_key, 100, 5000)

        self.assertEqual(self.stats.flow_stats[flow_key]['packets'], 100)
        self.assertEqual(self.stats.flow_stats[flow_key]['bytes'], 5000)

    def test_get_summary_statistics(self):
        """
        测试获取汇总统计
        """
        self.stats.update_flow_stats("flow1", 100, 5000)
        self.stats.update_flow_stats("flow2", 50, 2000)

        summary = self.stats.get_summary_statistics()

        self.assertEqual(summary['total_flows'], 2)
        self.assertEqual(summary['total_packets'], 150)
        self.assertEqual(summary['total_bytes'], 7000)

    def test_get_top_flows(self):
        """
        测试获取流量最多的流
        """
        self.stats.update_flow_stats("flow1", 100, 5000)
        self.stats.update_flow_stats("flow2", 50, 2000)
        self.stats.update_flow_stats("flow3", 200, 8000)

        top_flows = self.stats.get_top_flows(limit=2, sort_by='bytes')

        self.assertEqual(len(top_flows), 2)
        self.assertEqual(top_flows[0]['flow_key'], "flow3")


if __name__ == '__main__':
    unittest.main()