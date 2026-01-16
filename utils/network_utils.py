"""
网络工具模块
提供网络相关的实用函数
"""

import logging
import socket
import struct
from typing import Dict, List, Tuple, Optional
from ipaddress import ip_address, ip_network
import re

logger = logging.getLogger(__name__)


class NetworkUtils:
    """
    网络工具类
    """
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        验证IP地址有效性
        
        Args:  
            ip:  IP地址字符串
        
        Returns:  
            True: 有效的IP
        """
        try:
            ip_address(ip)
            return True
        except ValueError:  
            return False
    
    @staticmethod
    def is_valid_port(port: int) -> bool:
        """
        验证端口号有效性
        
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
    def is_valid_mac(mac: str) -> bool:
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
    def is_valid_cidr(cidr: str) -> bool:
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
    def ip_in_cidr(ip: str, cidr: str) -> bool:
        """
        检查IP是否在CIDR范围内
        
        Args: 
            ip: IP地址
            cidr: CIDR范围
        
        Returns:  
            True: IP在范围内
        """
        try:
            ip_obj = ip_address(ip)
            network = ip_network(cidr, strict=False)
            return ip_obj in network
        except ValueError:
            return False
    
    @staticmethod
    def mac_to_int(mac: str) -> int:
        """
        将MAC地址转换为整数
        
        Args:
            mac: MAC地址字符串
        
        Returns: 
            整数表示
        """
        try:
            parts = mac.replace(':', '').replace('-', '')
            return int(parts, 16)
        except Exception as e:
            logger.error(f"Error converting MAC to int: {e}")
            return 0
    
    @staticmethod
    def int_to_mac(mac_int: int) -> str:
        """
        将整数转换为MAC地址
        
        Args:
            mac_int: 整数表示
        
        Returns: 
            MAC地址字符串
        """
        try: 
            mac_hex = f'{mac_int:012x}'
            return ': '.join(mac_hex[i:i+2] for i in range(0, 12, 2))
        except Exception as e:
            logger.error(f"Error converting int to MAC: {e}")
            return '00:00:00:00:00:00'
    
    @staticmethod
    def ip_to_int(ip: str) -> int:
        """
        将IP地址转换为整数
        
        Args: 
            ip: IP地址字符串
        
        Returns:  
            整数表示
        """
        try:
            ip_obj = ip_address(ip)
            return int(ip_obj)
        except Exception as e:
            logger.error(f"Error converting IP to int:  {e}")
            return 0
    
    @staticmethod
    def int_to_ip(ip_int: int) -> str:
        """
        将整数转换为IP地址
        
        Args:
            ip_int: 整数表示
        
        Returns: 
            IP地址字符串
        """
        try:
            ip_obj = ip_address(ip_int)
            return str(ip_obj)
        except Exception as e:
            logger.error(f"Error converting int to IP: {e}")
            return '0.0.0.0'
    
    @staticmethod
    def get_network_address(ip: str, netmask: str) -> str:
        """
        获取网络地址
        
        Args:
            ip: IP地址
            netmask: 子网掩码
        
        Returns: 
            网络地址
        """
        try:
            ip_obj = ip_address(ip)
            mask = ip_address(netmask)
            
            # 计算网络地址
            network_int = int(ip_obj) & int(mask)
            return str(ip_address(network_int))
        except Exception as e:
            logger. error(f"Error calculating network address: {e}")
            return ip
    
    @staticmethod
    def get_broadcast_address(ip: str, netmask: str) -> str:
        """
        获取广播地址
        
        Args:
            ip: IP地址
            netmask: 子网掩码
        
        Returns: 
            广播地址
        """
        try: 
            network = ip_network(f'{ip}/{netmask}', strict=False)
            return str(network.broadcast_address)
        except Exception as e:
            logger.error(f"Error calculating broadcast address: {e}")
            return ip
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        检查是否为私有IP
        
        Args:
            ip: IP地址
        
        Returns: 
            True: 是私有IP
        """
        try:
            ip_obj = ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @staticmethod
    def is_loopback_ip(ip: str) -> bool:
        """
        检查是否为本地回环IP
        
        Args:
            ip: IP地址
        
        Returns: 
            True: 是回环IP
        """
        try:
            ip_obj = ip_address(ip)
            return ip_obj.is_loopback
        except ValueError:
            return False
    
    @staticmethod
    def is_multicast_ip(ip: str) -> bool:
        """
        检查是否为组播IP
        
        Args: 
            ip: IP地址
        
        Returns: 
            True: 是组播IP
        """
        try:
            ip_obj = ip_address(ip)
            return ip_obj.is_multicast
        except ValueError:
            return False
    
    @staticmethod
    def get_protocol_name(protocol_num: int) -> str:
        """
        获取协议名称
        
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
        return protocol_map.get(protocol_num, f'Unknown({protocol_num})')
    
    @staticmethod
    def get_service_name(port: int, protocol: str = 'TCP') -> str:
        """
        获取服务名称
        
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
        return common_services.get(port, f'Unknown({port})')
    
    @staticmethod
    def calculate_subnet_mask(prefix_length: int) -> str:
        """
        计算子网掩码
        
        Args:
            prefix_length:  前缀长度
        
        Returns: 
            子网掩码
        """
        try:
            mask = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF
            return '. '.join(str((mask >> (8 * (3 - i))) & 0xFF) for i in range(4))
        except Exception as e: 
            logger.error(f"Error calculating subnet mask: {e}")
            return '255.255.255.0'
    
    @staticmethod
    def is_reserved_ip(ip: str) -> bool:
        """
        检查是否为保留IP
        
        Args:
            ip: IP地址
        
        Returns: 
            True: 是保留IP
        """
        try:
            ip_obj = ip_address(ip)
            return (ip_obj.is_reserved or 
                   ip_obj. is_multicast or 
                   str(ip) == '255.255.255.255' or
                   str(ip).startswith('0.'))
        except ValueError:
            return False
    
    @staticmethod
    def extract_ip_from_url(url: str) -> Optional[str]:
        """
        从URL中提取IP地址
        
        Args:
            url: URL字符串
        
        Returns:  
            IP地址
        """
        try:
            # 简单的IP提取（实际应使用更复杂的解析）
            import re
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            match = re.search(ip_pattern, url)
            if match:
                ip = match.group(1)
                if NetworkUtils.is_valid_ip(ip):
                    return ip
        except Exception as e:
            logger.debug(f"Error extracting IP from URL: {e}")
        
        return None
    
    @staticmethod
    def get_tcp_flag_name(flags: int) -> str:
        """
        获取TCP标志名称
        
        Args:
            flags: TCP标志值
        
        Returns: 
            标志名称
        """
        flag_names = []
        
        if flags & 0x01:  # FIN
            flag_names.append('FIN')
        if flags & 0x02:  # SYN
            flag_names.append('SYN')
        if flags & 0x04:  # RST
            flag_names.append('RST')
        if flags & 0x08:  # PSH
            flag_names.append('PSH')
        if flags & 0x10:  # ACK
            flag_names.append('ACK')
        if flags & 0x20:  # URG
            flag_names. append('URG')
        if flags & 0x40:  # ECE
            flag_names.append('ECE')
        if flags & 0x80:  # CWR
            flag_names.append('CWR')
        
        return ','.join(flag_names) if flag_names else 'NONE'
    
    @staticmethod
    def calculate_ipv4_checksum(header: bytes) -> int:
        """
        计算IPv4校验和
        
        Args: 
            header: IP头字节
        
        Returns: 
            校验和
        """
        try:
            # 分割为16位字
            words = struct.unpack('!' + 'H' * (len(header) // 2), header)
            
            # 求和
            total = sum(words)
            
            # 处理进位
            while (total >> 16) > 0:
                total = (total & 0xFFFF) + (total >> 16)
            
            # 取反
            return ~total & 0xFFFF
        except Exception as e:
            logger.error(f"Error calculating checksum: {e}")
            return 0