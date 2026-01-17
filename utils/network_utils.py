"""
网络工具模块 - Python 3.6 兼容版本
提供网络相关的实用函数
"""

from __future__ import print_function
import logging
import re
import sys
from ipaddress import ip_address, ip_network

logger = logging.getLogger(__name__)


class NetworkUtils(object):
    """
    网络工具类 - Python 3.6 兼容
    """

    @staticmethod
    def is_valid_ip(ip):
        """
        验证IP地址有效性 - Python 3.6 兼容

        Args:
            ip: IP地址字符串

        Returns:
            True: 有效的IP
        """
        try:
            ip_address(ip if isinstance(ip, str) else str(ip))
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_port(port):
        """
        验证端口号有效性 - Python 3.6 兼容

        Args:
            port: 端口号

        Returns:
            True: 有效的端口
        """
        try:
            port_num = int(port)
            return 0 <= port_num <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_valid_mac(mac):
        """
        验证MAC地址有效性

        Args:
            mac: MAC地址字符串

        Returns:
            True: 有效的MAC
        """
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, mac))

    @staticmethod
    def is_valid_cidr(cidr):
        """
        验证CIDR表示法有效性

        Args:
            cidr:  CIDR字符串

        Returns:
            True: 有效的CIDR
        """
        try:
            ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def ip_in_cidr(ip, cidr):
        """
        检查IP是否在CIDR范围内

        Args:
            ip: IP地址
            cidr: CIDR范围

        Returns:
            True: IP在范围内
        """
        try:
            ip_obj = ip_address(ip if isinstance(ip, str) else str(ip))
            network = ip_network(cidr, strict=False)
            return ip_obj in network
        except ValueError:
            return False

    @staticmethod
    def is_private_ip(ip):
        """
        检查是否为私有IP

        Args:
            ip: IP地址

        Returns:
            True: 是私有IP
        """
        try:
            ip_obj = ip_address(ip if isinstance(ip, str) else str(ip))
            return ip_obj.is_private
        except ValueError:
            return False

    @staticmethod
    def get_protocol_name(protocol_num):
        """
        获取协议名称 - Python 3.6 兼容

        Args:
            protocol_num: 协议号

        Returns:
            协议名称
        """
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            47: 'GRE',
            50: 'ESP',
            51: 'AH'
        }
        return protocol_map.get(protocol_num, 'Unknown({0})'.format(protocol_num))

    @staticmethod
    def get_service_name(port, protocol='TCP'):
        """
        获取服务名称 - Python 3.6 兼容

        Args:
            port: 端口号
            protocol: 协议（TCP/UDP）

        Returns:
            服务名称
        """
        common_services = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT'
        }
        return common_services.get(port, 'Unknown({0})'.format(port))


# Python 版本检查
if sys.version_info < (3, 6):
    raise RuntimeError("需要 Python 3.6 或更高版本")