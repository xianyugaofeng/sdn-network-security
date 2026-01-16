"""
Mininet网络拓扑定义
创建测试网络拓扑
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.util import quietRun


class SDNSecurityTopo:
    """
    SDN安全系统测试拓扑
    """
    
    def __init__(self):
        self.net = None
    
    def create_topo(self):
        """
        创建网络拓扑
        
        拓扑结构: 
                    Controller
                        |
                  +-----+-----+
                  |           |
                 S1          S2
                /|\         /|\
               / | \       / | \
              H1 H2 H3    H4 H5 H6
        """
        
        # 创建Mininet网络
        self. net = Mininet(
            controller=Controller,
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True
        )
        
        # 添加控制器
        controller = self.net.addController('c0', port=6633)
        
        # 添加交换机
        s1 = self.net.addSwitch('s1')
        s2 = self.net. addSwitch('s2')
        
        # 添加主机
        hosts = []
        for i in range(1, 7):
            h = self.net.addHost(f'h{i}', ip=f'10.0.0.{i}')
            hosts.append(h)
        
        # 创建链接
        # S1连接H1, H2, H3
        self.net.addLink(s1, hosts[0])
        self.net.addLink(s1, hosts[1])
        self.net.addLink(s1, hosts[2])
        
        # S2连接H4, H5, H6
        self.net.addLink(s2, hosts[3])
        self.net.addLink(s2, hosts[4])
        self.net.addLink(s2, hosts[5])
        
        # S1和S2相连
        self.net.addLink(s1, s2)
        
        return self.net
    
    def start(self):
        """
        启动网络
        """
        if self.net is None:
            self.create_topo()
        
        self.net.start()
        print("Network started")
        print("Network topology created successfully")
    
    def stop(self):
        """
        停止网络
        """
        if self. net:
            self.net. stop()
            print("Network stopped")
    
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