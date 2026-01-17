"""
动态防火墙模块 - Python 3.6 兼容版本
支持实时规则下发、黑白名单、协议过滤等功能
"""

from __future__ import print_function
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class DynamicFirewall(object):
    """
    动态防火墙类 - Python 3.6 兼容版本
    """

    def __init__(self, controller):
        """
        初始化防火墙

        Args:
            controller: SDN控制器实例
        """
        self. controller = controller
        self.rules = []  # 防火墙规则列表
        self.blacklist = set()  # 黑名单IP
        self.whitelist = set()  # 白名单IP
        self.load_rules_from_file()
        logger.info("防火墙初始化成功")

    def load_rules_from_file(self, config_file='config/rules.json'):
        """
        从配置文件加载规则 - Python 3.6 兼容
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                self.rules = config.get('rules', [])
                self.blacklist = set(config.get('blacklist', []))
                self.whitelist = set(config. get('whitelist', []))
                logger.info("已加载 %d 条防火墙规则" % len(self.rules))
        except IOError:
            logger.warning("配置文件 %s 未找到，使用空规则" % config_file)
            self.rules = []
        except Exception as e:
            logger.error("加载规则失败: %s" % str(e))
            self.rules = []

    def check_policy(self, flow_info):
        """
        检查流是否符合防火墙策略 - Python 3.6 兼容

        Args:
            flow_info: 流信息字典

        Returns:
            True: 允许该流
            False: 阻止该流
        """
        try:
            # 先检查黑名单
            src_ip = flow_info.get('ip_src')
            if src_ip and src_ip in self.blacklist:
                logger.warning("数据包来自黑名单IP: %s" % src_ip)
                return False

            # 检查白名单
            if src_ip and src_ip in self.whitelist:
                return True

            # 检查防火墙规则
            for rule in self.rules:
                if self._match_rule(flow_info, rule):
                    action = rule.get('action', 'DENY')
                    if action == 'ALLOW':
                        return True
                    elif action == 'DENY':
                        return False

            # 默认策略：允许
            return True
        except Exception as e:
            logger.error("策略检查异常: %s" % str(e))
            return True

    def _match_rule(self, flow_info, rule):
        """
        检查流是否匹配规则 - Python 3.6 兼容

        Args:
            flow_info: 流信息字典
            rule: 规则字典

        Returns:
            True: 匹配
        """
        try:
            # 检查协议
            rule_protocol = rule.get('protocol', 'ALL')
            if rule_protocol != 'ALL':
                if flow_info.get('protocol') != rule_protocol:
                    return False

            # 检查端口
            rule_port = rule.get('tp_dst')
            if rule_port is not None:
                if flow_info.get('tp_dst') != rule_port:
                    return False

            return True
        except Exception as e:
            logger.debug("规则匹配异常: %s" % str(e))
            return False

    def add_rule(self, rule):
        """
        添加防火墙规则 - Python 3.6 兼容

        Args:
            rule: 规则字典

        Returns:
            True: 添加成功
        """
        try:
            if 'action' not in rule or 'protocol' not in rule:
                logger.error("规则缺少必需字段")
                return False

            self.rules.append(rule)
            logger.info("规则已添加:  %s" % rule. get('name', 'Unknown'))
            return True
        except Exception as e:
            logger.error("添加规则失败: %s" % str(e))
            return False

    def add_to_blacklist(self, ip):
        """
        添加IP到黑名单 - Python 3.6 兼容

        Args:
            ip: IP地址

        Returns:
            True: 添加成功
        """
        try:
            self.blacklist.add(ip)
            logger.info("IP已加入黑名单: %s" % ip)
            return True
        except Exception as e:
            logger.error("添加到黑名单失败: %s" % str(e))
            return False

    def install_base_rules(self, datapath):
        """
        在交换机上安装基础规则 - Python 3.6 兼容

        Args:
            datapath: 交换机对象
        """
        try:
            logger.info("在交换机 %d 上安装基础规则" % datapath.id)
        except Exception as e:
            logger.error("安装基础规则失败: %s" % str(e))

    def get_statistics(self):
        """
        获取防火墙统计信息 - Python 3.6 兼容

        Returns:
            统计信息字典
        """
        return {
            'total_rules':  len(self.rules),
            'blacklist_size': len(self.blacklist),
            'whitelist_size': len(self.whitelist),
            'timestamp': datetime.now().isoformat()
        }