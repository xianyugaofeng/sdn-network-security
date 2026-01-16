"""
入侵检测模块 (Intrusion Detection Module)

提供多层入侵检测和告警功能：
- DetectionEngine: 入侵检测引擎
- SnortIntegration: Snort集成模块

使用示例:
    from modules.intrusion_detection import DetectionEngine, SnortIntegration
    
    ids = DetectionEngine()
    alert = ids.detect(flow_info)
    
    snort = SnortIntegration()
    snort.add_custom_rule(rule)
"""

from .detection_engine import DetectionEngine
from .snort_integration import SnortIntegration

__all__ = [
    'DetectionEngine',
    'SnortIntegration'
]

__version__ = '1.0.0'
__doc__ = """
入侵检测模块
===========

支持以下功能：
1. 多层检测机制
   - 协议异常检测
   - 已知攻击特征检测
   - Snort规则匹配
   - 会话异常检测

2. 攻击特征库
   - 端口扫描
   - SYN泛洪
   - UDP泛洪
   - ICMP扫描
   - SQL注入
   - XSS攻击

3. 告警管理
   - 告警生成
   - 告警统计
   - 告警存储

4. Snort集成
   - 规则管理
   - 规则匹配
   - 告警解析
   - 规则导出

主要类：
-------
- DetectionEngine: 入侵检测引擎，支持多种检测方法
- SnortIntegration: Snort入侵检测系统集成

示例代码：
--------
from modules.intrusion_detection import DetectionEngine, SnortIntegration

# 初始化检测引擎
ids = DetectionEngine()

# 检测流
alert = ids.detect(flow_info)
if alert:
    print(f"Alert:  {alert}")

# 初始化Snort集成
snort = SnortIntegration(use_builtin=True)

# 添加自定义规则
custom_rule = {
    'rule_id': 3001,
    'name': 'Custom Attack',
    'patterns': ['malicious_pattern'],
    'severity': 'HIGH'
}
snort.add_custom_rule(custom_rule)

# 检查数据包
alerts = snort.check_packet_against_rules(payload)
"""