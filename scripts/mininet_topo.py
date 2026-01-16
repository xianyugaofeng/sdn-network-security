"""
Mininet网络拓扑定义
创建测试网络拓扑用于SDN安全系统验证
"""

import time
import sys
import os
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import quietRun, macColonHex
from mininet.clean import cleanup
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SDNSecurityTopo:
    """
    SDN安全系统测试拓扑

    拓扑结构:
              Controller (c0)
                    |
              ┌─────┴─────┐
              |           |
             S1          S2
            /|\         /|\
           / | \       / | \
          H1 H2 H3    H4 H5 H6

    说明:
    - 2个OpenFlow交换机 (S1, S2)
    - 6个主机 (H1-H6)
    - S1连接H1, H2, H3
    - S2连接H4, H5, H6
    - S1和S2相连
    - 控制器监听地址: 127.0.0.1:6633
    """

    def __init__(self, controller_ip='127.0.0.1', controller_port=6633):
        """
        初始化拓扑

        Args:
            controller_ip:  控制器IP地址
            controller_port: 控制器端口
        """
        self.net = None
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.hosts = {}
        self.switches = {}
        self.controller = None
        logger.info(f"SDNSecurityTopo initialized with controller at {controller_ip}:{controller_port}")

    def create_topo(self):
        """
        创建网络拓扑

        Returns:
            Mininet网络实例
        """
        logger.info("=" * 60)
        logger.info("Creating SDN Security System Network Topology")
        logger.info("=" * 60)

        try:
            # 创建Mininet网络实例
            logger.info("Creating Mininet network...")
            self.net = Mininet(
                controller=lambda name:  Controller(
                    name,
                    ip=self.controller_ip,
                    port=self.controller_port,
                    protocol='tcp'
                ),
                switch=OVSSwitch,
                link=TCLink,
                autoSetMacs=True,
                autoStaticArp=False,
                build=False  # 先不启动
            )

            logger.info("✓ Mininet network instance created")

            # 添加控制器
            logger.info("Adding SDN controller...")
            self.controller = self.net.addController(
                'c0',
                controller=Controller,
                ip=self.controller_ip,
                port=self. controller_port,
                protocol='tcp'
            )
            logger.info(f"✓ Controller added:  {self.controller_ip}:{self.controller_port}")

            # 添加交换机
            logger. info("Adding OpenFlow switches...")
            s1 = self.net.addSwitch(
                's1',
                dpid='0000000000000001',
                protocols='OpenFlow13'
            )
            s2 = self.net.addSwitch(
                's2',
                dpid='0000000000000002',
                protocols='OpenFlow13'
            )
            self.switches['s1'] = s1
            self.switches['s2'] = s2
            logger.info("✓ Added switches: s1, s2")

            # 添加主机
            logger.info("Adding hosts...")
            for i in range(1, 7):
                host_name = f'h{i}'
                host_ip = f'10.0.0.{i}'
                host_mac = f'00:00:00:00:00:0{i}' if i < 10 else f'00:00:00:00:00:{i}'

                h = self.net.addHost(
                    host_name,
                    ip=host_ip,
                    mac=host_mac,
                    defaultRoute='via 10.0.0.254'
                )
                self. hosts[host_name] = h
                logger.debug(f"  Added host: {host_name} ({host_ip})")

            logger.info(f"✓ Added {len(self.hosts)} hosts: h1-h6")

            # 创建链接 - S1连接H1, H2, H3
            logger.info("Creating links:  S1 <-> H1, H2, H3")
            for i in range(1, 4):
                host = self.hosts[f'h{i}']
                link = self.net.addLink(
                    s1,
                    host,
                    bw=1000,  # 1Gbps
                    delay='1ms',
                    loss=0
                )
                logger.debug(f"  s1 <-> h{i}")

            # 创建链接 - S2连接H4, H5, H6
            logger.info("Creating links: S2 <-> H4, H5, H6")
            for i in range(4, 7):
                host = self.hosts[f'h{i}']
                link = self.net. addLink(
                    s2,
                    host,
                    bw=1000,  # 1Gbps
                    delay='1ms',
                    loss=0
                )
                logger.debug(f"  s2 <-> h{i}")

            # 创建链接 - S1和S2相连
            logger.info("Creating link: S1 <-> S2")
            link_inter = self.net.addLink(
                s1,
                s2,
                bw=100,  # 100Mbps
                delay='2ms',
                loss=0
            )
            logger.info("✓ Interswitch link created")

            # 构建拓扑（执行addHost和addSwitch之后，必须调用build）
            logger.info("Building network topology...")
            self.net. build()
            logger.info("✓ Network topology built successfully")

            return self.net

        except Exception as e:
            logger. error(f"Error creating topology:  {e}")
            raise

    def start(self):
        """
        启动网络
        """
        if self.net is None:
            self.create_topo()

        try:
            logger.info("=" * 60)
            logger. info("Starting Network")
            logger.info("=" * 60)

            logger.info("Starting Mininet network...")
            self.net.start()
            logger.info("✓ Network started")

            # 等待OpenFlow连接建立
            logger.info("Waiting for OpenFlow connections to establish...")
            time.sleep(2)

            # 测试基本连接
            logger.info("Testing network connectivity...")
            result = self.net.pingAll(timeout=2)

            if result == 0:
                logger.info("✓ All hosts can reach each other")
            else:
                logger.warning(f"⚠ Some hosts cannot reach each other (failed pings: {result})")

            # 打印网络信息
            self._print_network_info()

            logger.info("=" * 60)
            logger.info("Network startup completed successfully!")
            logger.info("=" * 60)

        except Exception as e:
            logger. error(f"Error starting network: {e}")
            self.stop()
            raise

    def stop(self):
        """
        停止网络
        """
        if self. net:
            try:
                logger.info("Stopping Mininet network...")
                self.net.stop()
                logger.info("✓ Network stopped")

                # 清理OpenFlow相关进程
                logger.info("Cleaning up OpenFlow processes...")
                cleanup()
                logger.info("✓ Cleanup completed")

            except Exception as e:
                logger. error(f"Error stopping network:  {e}")

    def cli(self):
        """
        启动Mininet CLI（交互式命令行）
        """
        if self.net is None:
            logger.error("Network not started.  Call start() first.")
            return

        try:
            logger.info("=" * 60)
            logger. info("Starting Mininet CLI")
            logger.info("=" * 60)
            logger.info("\nCommon commands:")
            logger.info("  help          - Show help information")
            logger.info("  nodes         - List all nodes")
            logger.info("  net           - List network links")
            logger.info("  dump          - Show node information")
            logger.info("  h1 ping h2    - Ping from h1 to h2")
            logger.info("  iperf         - Run iperf between hosts")
            logger.info("  exit          - Exit CLI\n")

            CLI(self.net)

        except KeyboardInterrupt:
            logger. info("\nExiting CLI...")

    def _print_network_info(self):
        """
        打印网络信息
        """
        logger.info("=" * 60)
        logger.info("Network Information")
        logger.info("=" * 60)

        # 打印控制器信息
        logger.info("\nController:")
        logger.info(f"  Address: {self.controller_ip}:{self.controller_port}")

        # 打印交换机信息
        logger.info("\nSwitches:")
        for switch_name, switch in self. switches.items():
            logger. info(f"  {switch_name} (DPID: {switch. dpid})")

        # 打印主机信息
        logger.info("\nHosts:")
        for host_name, host in self.hosts.items():
            ip = host.IP()
            mac = host.MAC()
            logger.info(f"  {host_name: 4s} - IP: {ip: 15s} MAC: {mac}")

        # 打印链接信息
        logger.info("\nLinks:")
        for link in self.net.links:
            logger.info(f"  {link. intf1.node. name} <-> {link.intf2.node.name}")

        logger.info("=" * 60)

    def run_test_scenario(self, scenario_name='basic'):
        """
        运行测试场景

        Args:
            scenario_name: 场景名称 ('basic', 'heavy', 'attack')
        """
        if self.net is None:
            logger.error("Network not started. Call start() first.")
            return

        logger.info("=" * 60)
        logger.info(f"Running Test Scenario: {scenario_name}")
        logger.info("=" * 60)

        try:
            if scenario_name == 'basic':
                self._test_basic_connectivity()
            elif scenario_name == 'heavy':
                self._test_heavy_traffic()
            elif scenario_name == 'attack':
                self._test_attack_patterns()
            else:
                logger.warning(f"Unknown scenario: {scenario_name}")

        except Exception as e:
            logger.error(f"Error running test scenario: {e}")

    def _test_basic_connectivity(self):
        """
        基本连接测试
        """
        logger.info("Testing basic connectivity...")

        h1 = self.hosts['h1']
        h2 = self.hosts['h2']
        h4 = self.hosts['h4']

        # 同子网ping测试
        logger.info("  Testing same subnet connectivity (h1 -> h2)...")
        result = h1.cmd('ping -c 3 10.0.0.2')
        if '3 received' in result:
            logger. info("  ✓ Same subnet connectivity OK")
        else:
            logger.warning("  ⚠ Same subnet connectivity failed")

        # 不同子网ping测试
        logger.info("  Testing different subnet connectivity (h1 -> h4)...")
        result = h1.cmd('ping -c 3 10.0.0.4')
        if '3 received' in result:
            logger. info("  ✓ Different subnet connectivity OK")
        else:
            logger.warning("  ⚠ Different subnet connectivity failed")

    def _test_heavy_traffic(self):
        """
        重流量测试
        """
        logger.info("Testing heavy traffic...")

        h1 = self.hosts['h1']
        h2 = self.hosts['h2']

        logger.info("  Starting iperf server on h2...")
        h2.cmd('iperf -s -u &')
        time.sleep(1)

        logger.info("  Running iperf client from h1...")
        result = h1.cmd('iperf -c 10.0.0.2 -u -t 10 -b 100M')
        logger.info(f"  Iperf result:\n{result}")

        # 停止iperf服务器
        h2.cmd('killall iperf')

    def _test_attack_patterns(self):
        """
        攻击模式测试（模拟）
        """
        logger.info("Testing attack patterns...")

        h1 = self.hosts['h1']

        # 模拟端口扫描（使用nc）
        logger.info("  Simulating port scan from h1...")
        for port in [22, 23, 80, 443, 3306]:
            h1.cmd(f'timeout 1 nc -zv 10.0.0.2 {port} 2>/dev/null &')

        time.sleep(2)
        logger.info("  ✓ Attack pattern simulation completed")

    def get_host(self, name):
        """
        获取主���对象

        Args:
            name: 主机名称 (h1-h6)

        Returns:
            主机对象
        """
        return self.hosts. get(name)

    def get_switch(self, name):
        """
        获取交换机对象

        Args:
            name: 交换机名称 (s1, s2)

        Returns:
            交换机对象
        """
        return self.switches.get(name)

    def print_host_info(self, host_name):
        """
        打印主机详细信息

        Args:
            host_name: 主机名称
        """
        if host_name not in self.hosts:
            logger.warning(f"Host {host_name} not found")
            return

        host = self.hosts[host_name]

        logger.info(f"\nHost Information:  {host_name}")
        logger.info(f"  IP Address: {host.IP()}")
        logger.info(f"  MAC Address: {host.MAC()}")
        logger.info(f"  Process ID: {host.pid}")
        logger.info(f"  Interfaces:  {host.intfs. keys()}")

    def enable_traffic_monitoring(self):
        """
        启用流量监控
        在所有主机上启动tcpdump进行流量监控
        """
        logger.info("Enabling traffic monitoring on all hosts...")

        for host_name, host in self.hosts.items():
            log_file = f"logs/{host_name}_traffic.pcap"
            host.cmd(f'tcpdump -i {host_name}-eth0 -w {log_file} > /dev/null 2>&1 &')
            logger.info(f"  ✓ Traffic monitoring started on {host_name}")

    def disable_traffic_monitoring(self):
        """
        禁用流量监控
        停止所有主机上的tcpdump进程
        """
        logger.info("Disabling traffic monitoring on all hosts...")

        for host_name, host in self.hosts.items():
            host.cmd('killall tcpdump 2>/dev/null')
            logger.info(f"  ✓ Traffic monitoring stopped on {host_name}")


def main():
    """
    主程序
    """
    # 设置日志级别
    setLogLevel('info')

    logger.info("\n")
    logger.info("╔════════════════════════════════════════════════════════╗")
    logger.info("║   SDN Network Security System - Mininet Topology       ║")
    logger.info("║                                                        ║")
    logger.info("║   This script creates a test network topology for    ║")
    logger.info("║   SDN security system development and testing        ║")
    logger.info("╚════════════════════════════════════════════════════════╝")
    logger.info("\n")

    # 创建拓扑
    topo = SDNSecurityTopo(
        controller_ip='127.0.0.1',
        controller_port=6633
    )

    try:
        # 创建并启动网络
        topo.create_topo()
        topo.start()

        # 启用流量监控
        topo.enable_traffic_monitoring()

        logger.info("\n")
        logger.info("Network is ready for testing.  Enter 'quit' or 'exit' to stop.\n")

        # 启动CLI交互式界面
        topo.cli()

        # 停止流量监控
        topo.disable_traffic_monitoring()

    except KeyboardInterrupt:
        logger.info("\n\nKeyboard interrupt received. Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        logger.info("Cleaning up...")
        topo.stop()
        logger.info("\n✓ Mininet topology stopped successfully\n")


if __name__ == '__main__':
    # 检查是否以root身份运行（Mininet需要）
    if os.geteuid() != 0:
        logger.error("This script must be run as root (use sudo)")
        sys.exit(1)

    try:
        main()
    except SystemExit:
        pass
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)