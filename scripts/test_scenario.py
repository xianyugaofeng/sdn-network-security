"""
测试场景脚本
定义各种攻击和正常流量的测试场景
"""

import time
from scapy.all import IP, TCP, UDP, ICMP, send
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestScenario:
    """
    测试场景类
    """

    def __init__(self, target_ip='192.168.1.1'):
        """
        初始化测试场景

        Args:
            target_ip: 目标IP地址
        """
        self.target_ip = target_ip

    def test_normal_http(self):
        """
        测试正常HTTP流量
        """
        logger.info("Testing normal HTTP traffic...")

        packet = IP(dst=self.target_ip) / TCP(dport=80, flags='S')
        send(packet, verbose=False)

        logger.info("HTTP test completed")

    def test_normal_https(self):
        """
        测试正常HTTPS流量
        """
        logger.info("Testing normal HTTPS traffic...")

        packet = IP(dst=self.target_ip) / TCP(dport=443, flags='S')
        send(packet, verbose=False)

        logger.info("HTTPS test completed")

    def test_port_scan(self):
        """
        测试端口扫描
        """
        logger.info("Testing port scan attack...")

        common_ports = [22, 23, 25, 80, 443, 3306, 3389]

        for port in common_ports:
            packet = IP(dst=self.target_ip) / TCP(dport=port, flags='S')
            send(packet, verbose=False)
            time.sleep(0.1)

        logger.info("Port scan test completed")

    def test_syn_flood(self):
        """
        测试SYN泛洪攻击
        """
        logger.info("Testing SYN flood attack...")

        for i in range(100):
            packet = IP(dst=self.target_ip) / TCP(dport=80, flags='S')
            send(packet, verbose=False)

        logger.info("SYN flood test completed")

    def test_udp_flood(self):
        """
        测试UDP泛洪攻击
        """
        logger.info("Testing UDP flood attack...")

        for i in range(100):
            packet = IP(dst=self.target_ip) / UDP(dport=53)
            send(packet, verbose=False)

        logger.info("UDP flood test completed")

    def test_icmp_sweep(self):
        """
        测试ICMP扫描
        """
        logger.info("Testing ICMP sweep...")

        for i in range(10):
            target = f"192.168.1.{i + 1}"
            packet = IP(dst=target) / ICMP()
            send(packet, verbose=False)

        logger.info("ICMP sweep test completed")


def main():
    """
    主程序
    """
    scenario = TestScenario(target_ip='192.168.1.1')

    # 测试正常流量
    scenario.test_normal_http()
    time.sleep(2)
    scenario.test_normal_https()
    time.sleep(2)

    # 测试攻击流量
    scenario.test_port_scan()
    time.sleep(2)
    scenario.test_syn_flood()
    time.sleep(2)
    scenario.test_icmp_sweep()


if __name__ == '__main__':
    main()