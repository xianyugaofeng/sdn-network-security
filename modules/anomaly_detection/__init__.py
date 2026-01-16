"""
异常检测模块 (Anomaly Detection Module)

提供基于机器学习的异常检测功能：
- KMeansAnalyzer: K-means聚类异常检测
- FeatureExtractor: 流量特征提取器

使用示例:
    from modules.anomaly_detection import KMeansAnalyzer, FeatureExtractor
    
    analyzer = KMeansAnalyzer(k_clusters=3)
    anomalies = analyzer.detect(flows)
    
    extractor = FeatureExtractor()
    features = extractor.extract(flow)
"""

from .kmeans_analyzer import KMeansAnalyzer, FeatureExtractor as KMeansFeatureExtractor
from .feature_extractor import FeatureExtractor

__all__ = [
    'KMeansAnalyzer',
    'FeatureExtractor'
]

__version__ = '1.0.0'
__doc__ = """
异常检测模块
===========

支持以下功能：
1. 特征提取
   - 数据包大小
   - 包速率
   - 协议特征
   - 端口特征
   - TTL特征
   - 流持续时间
   - 信息熵
   - 上下行比例

2. 特征处理
   - Min-Max归一化
   - Z-score标准化
   - 特征重要性加权

3. K-means聚类
   - 动态质心初始化
   - 迭代聚类
   - 收敛检测

4. 异常识别
   - 离群点检测
   - 异常评分
   - 异常报告

主要类：
-------
- FeatureExtractor: 流量特征提取，从网络流中提取8维特征向量
- KMeansAnalyzer: K-means异常检测，使用聚类算法识别异常流

示例代码：
--------
from modules.anomaly_detection import KMeansAnalyzer, FeatureExtractor

# 初始化特征提取器
extractor = FeatureExtractor()
features = extractor.extract(flow_info)
print(f"Extracted features: {features}")

# 初始化K-means分析器
analyzer = KMeansAnalyzer(k_clusters=3, max_iterations=100)

# 检测异常
recent_flows = [... 流列表...]
anomalies = analyzer.detect(recent_flows)

for anomaly in anomalies: 
    print(f"Anomaly detected: {anomaly}")

# 批量提取特征
feature_matrix = extractor.extract_batch(flows)

# 获取特征重要性
importance = extractor. get_feature_importance()
"""