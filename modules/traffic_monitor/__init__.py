"""
流量监控模块 (Traffic Monitor Module)

提供实时流量采集和统计分析功能：
- TrafficCollector: 流量采集器
- StatisticsCollector: 统计收集器
- PerformanceMetrics: 性能指标收集器

使用示例: 
    from modules.traffic_monitor import TrafficCollector, StatisticsCollector
    
    collector = TrafficCollector()
    collector.record_flow(flow_info)
    
    stats = StatisticsCollector()
    stats.update_flow_stats(flow_key, packet_count, byte_count)
"""

from .traffic_collector import TrafficCollector
from .statistics import StatisticsCollector, PerformanceMetrics

__all__ = [
    'TrafficCollector',
    'StatisticsCollector',
    'PerformanceMetrics'
]

__version__ = '1.0.0'
__doc__ = """
流量监控模块
===========

支持以下功能：
1. 实时流量采集
2. 流量统计分析
3. 带宽监测
4. 协议分布统计
5. 端口分析
6. IP通信矩阵
7. 性能指标收集
8. 统计报告生成

主要类：
-------
- TrafficCollector: 实时流量采集和存储
- StatisticsCollector: 流量统计收集和分析
- PerformanceMetrics: 性能指标记录和分析

示例代码：
--------
from modules. traffic_monitor import TrafficCollector, StatisticsCollector

# 初始化采集器
collector = TrafficCollector(max_flows=10000)

# 记录流
collector.record_flow(flow_info)

# 获取最近流
recent_flows = collector.get_recent_flows(window=300)

# 初始化统计器
stats = StatisticsCollector()
stats.update_flow_stats(flow_key, 100, 5000)

# 生成报告
stats.generate_report(flows, 'report.json')
"""