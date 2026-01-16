"""
防火墙模块 (Firewall Module)

提供动态防火墙和规则引擎功能：
- DynamicFirewall:  动态防火墙实现
- RuleEngine: 防火墙规则引擎

使用示例: 
    from modules.firewall import DynamicFirewall, RuleEngine
    
    firewall = DynamicFirewall(controller)
    rule_engine = RuleEngine()
    
    # 检查流是否符合策略
    if firewall.check_policy(flow_info):
        # 允许流量
        pass
"""

from .dynamic_firewall import DynamicFirewall
from . rule_engine import RuleEngine

__all__ = [
    'DynamicFirewall',
    'RuleEngine'
]

__version__ = '1.0.0'
__doc__ = """
防火墙模块
===========

支持以下功能：
1. 动态流表规则下发
2. 黑白名单管理
3. 协议过滤
4. 规则优先级管理
5. 实时规则更新

主要类：
-------
- DynamicFirewall:  防火墙主类，负责策略检查和规则管理
- RuleEngine: 规则引擎，负责规则匹配和验证

示例代码：
--------
from modules.firewall import DynamicFirewall

# 初始化防火墙
firewall = DynamicFirewall(controller)

# 添加规则
rule = {
    'id': 1,
    'action': 'DENY',
    'protocol': 'TCP',
    'dst_port': 22,
    'priority': 100
}
firewall.add_rule(rule)

# 检查流
if firewall.check_policy(flow_info):
    print("Flow allowed")
else:
    print("Flow blocked")
"""