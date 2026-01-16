"""
Mininet网络拓扑定义
创建测试网络拓扑用于SDN安全系统验证
"""

from mininet. net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet. link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import quietRun, macColonHex
import logging

logging.basicConfig(level=logging.INFO)
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
    """

    def __init__(self, controller_ip='127.0.0.1', controller_port=6633):
        """
        初始化拓扑

        Args:
            controller_ip: 控制器IP
            controller_port: 控制器端口
        """
        self.net = None
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.hosts = {}
        self.switches = {}

    def create_topo(self):
        """
        创建网络拓扑
        """
        logger.info("Creating network topology...")

        # 创建Mininet网络
        self.net = Mininet(
            controller=lambda name:  Controller(
                name,
                ip=self.controller_ip,
                port=self.controller_port
            ),
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True,
            autoStaticArp=False
        )

        # 添加控制器
        logger.info("Adding controller...")
        controller = self.net.addController(
            'c0',
            ip=self.controller_ip,
            port=self.controller_port
        )

        # 添加交换机
        logger.info("Adding switches...")
        s1 = self.net.addSwitch('s1', dpid='0000000000000001')
        s2 = self.net.addSwitch('s2', dpid='0000000000000002')
        self.switches['s1'] = s1
        self.switches['s2'] = s2

        # 添加主机
        logger. info("Adding hosts...")
        for i in range(1, 7):
            h = self.net.addHost(
                f'h{i}',
                ip=f'10.0.0.{i}',
                mac=macColonHex(i)
            )
            self.hosts[f'h{i}'] = h

        # 创建链接
        logger.info("Adding links...")

        # S1连接H1, H2, H3
        for i in range(1, 4):
            self.net.addLink(s1, self.hosts[f'h{i}'])

        # S2连接H4, H5, H6
        for i in range(4, 7):
            self.net.addLink(s2, self.hosts[f'h{i}'])

        # S1和S2相连（配置带宽和延迟）
        self. net.addLink(s1, s2, bw=100, delay='1ms')

        logger. info("Topology created successfully")
        return self.net

    def start(self):
        """
        启动网络
        """
        if self.net is None:
            self.create_topo()

        logger.info("Starting network...")
        self.net.start()

        # 测试连接
        logger.info("Testing connectivity...")
        self.net.pingAll(timeout=2)

        logger.info("Network started successfully")

        # 打印拓扑信息
        self._print_topo_info()

    def stop(self):
        """
        停止网络
        """
        if self.net:
            logger.info("Stopping network...")
            self.net.stop()
            logger.info("Network stopped")

    
    def cli(self):
        """
        启动Mininet CLI
        """
        if self.net:
            CLI(self.net)


def main():
    """
    主程序
    """
    setLogLevel('info')
    
    topo = SDNSecurityTopo()
    topo.start()
    
    try:
        topo.cli()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        topo.stop()


if __name__ == '__main__':
    main()