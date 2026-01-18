"""
流量特征提取器
从网络流中提取机器学习特征
"""

import logging
import math
from typing import Dict, List, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class FeatureExtractor: 
    """
    特征提取器
    """
    
    # 特征索引映射
    FEATURE_NAMES = [
        'packet_size',
        'packet_rate',
        'protocol_type',
        'port_feature',
        'ttl_feature',
        'duration',
        'entropy',
        'direction_ratio'
    ]
    
    def __init__(self):
        """
        初始化特征提取器
        """
        self.min_values = {}
        self.max_values = {}
        self._initialize_bounds()
    
    def _initialize_bounds(self):
        """
        初始化特征的最小最大值范围
        """
        self.min_values = {
            'packet_size': 0,
            'packet_rate': 0,
            'protocol_type':  0,
            'port_feature': 0,
            'ttl_feature': 0,
            'duration': 0,
            'entropy': 0,
            'direction_ratio': 0
        }
        
        self.max_values = {
            'packet_size': 65535,
            'packet_rate': 10000,
            'protocol_type': 1,
            'port_feature': 1,
            'ttl_feature': 1,
            'duration': 3600,
            'entropy': 8,
            'direction_ratio': 1
        }
    
    def extract(self, flow:  Dict) -> List[float]:
        """
        从流中提取特征向量
        
        Args: 
            flow: 流信息字典
        
        Returns: 
            特征向量列表
        """
        features = []
        
        # 提取各个特征
        features.append(self. extract_packet_size(flow))
        features.append(self. extract_packet_rate(flow))
        features.append(self. extract_protocol_feature(flow))
        features.append(self.extract_port_feature(flow))
        features.append(self.extract_ttl_feature(flow))
        features.append(self.extract_duration_feature(flow))
        features.append(self.extract_entropy_feature(flow))
        features.append(self.extract_direction_ratio(flow))
        
        # 归一化特征
        normalized_features = self. normalize_features(features)
        
        return normalized_features
    
    def extract_packet_size(self, flow: Dict) -> float:
        """
        提取数据包大小特征
        
        Args: 
            flow: 流信息
        
        Returns:
            特征值
        """
        packet_length = flow.get('packet_length', 0)
        # 特征值范围：[0, 65535]
        return min(float(packet_length), 65535.0)
    
    def extract_packet_rate(self, flow: Dict) -> float:
        """
        提取数据包速率特征
        
        Args:
            flow: 流信息
        
        Returns: 
            特征值
        """
        # 简化实现，实际应计算时间窗口内的包速率
        # 返回值范围：[0, 10000]
        return 1.0  # 默认值
    
    def extract_protocol_feature(self, flow: Dict) -> float:
        """
        提取协议特征
        
        Args: 
            flow: 流信息
        
        Returns:
            特征值
        """
        protocol = flow.get('protocol', 'UNKNOWN')
        protocol_encoding = {
            'TCP': 0.0,
            'UDP': 0.33,
            'ICMP': 0.67,
            'OTHER': 1.0
        }
        return protocol_encoding.get(protocol, 0.5)
    
    def extract_port_feature(self, flow:  Dict) -> float:
        """
        提取端口特征
        
        Args:
            flow: 流信息
        
        Returns:
            特征值
        """
        dst_port = flow.get('tp_dst', 0)
        
        if dst_port == 0:
            return 0.0
        elif dst_port < 1024:
            # 特权端口
            return 0.25
        elif dst_port < 49152:
            # 注册端口
            return 0.5
        else:
            # 动态/私有端口
            return 0.75
    
    def extract_ttl_feature(self, flow: Dict) -> float:
        """
        提取TTL特征
        
        Args: 
            flow: 流信息
        
        Returns:
            特征值
        """
        ttl = flow.get('ttl', 64)
        # 归一化到[0, 1]
        return min(float(ttl) / 255.0, 1.0)
    
    def extract_duration_feature(self, flow: Dict) -> float:
        """
        提取流持续时间特征
        
        Args:
            flow:  流信息
        
        Returns:
            特征值
        """
        # 简化实现，实际应计算first_seen和last_seen的差值
        return 0.1
    
    def extract_entropy_feature(self, flow: Dict) -> float:
        """
        提取信息熵特征（用于检测数据混淆）
        
        Args:
            flow: 流信息
        
        Returns:
            特征值
        """
        # 计算有效负载的信息熵
        # 如果可用，使用payload；否则返回默认值
        payload = flow. get('payload', '')
        
        if not payload:
            return 0.0
        
        entropy = self._calculate_entropy(payload)
        return min(entropy / 8.0, 1.0)  # 归一化到[0, 1]
    
    def extract_direction_ratio(self, flow: Dict) -> float:
        """
        提取上下行比例特征
        
        Args: 
            flow: 流信息
        
        Returns:
            特征值
        """
        # 简化实现，实际应计算上下行数据量比例
        return 0.5
    
    def _calculate_entropy(self, data:  str) -> float:
        """
        计算��据的Shannon熵
        
        Args: 
            data: 数据字符串
        
        Returns: 
            熵值
        """
        if not data:
            return 0.0
        
        # 计算每个字节的频率
        byte_counts = defaultdict(int)
        for byte in data. encode():
            byte_counts[byte] += 1
        
        # 计算Shannon熵
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts. values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def normalize_features(self, features: List[float]) -> List[float]:
        """
        特征归一化（Min-Max标准化）
        
        Args:
            features:  原始特征列表
        
        Returns:
            归一化后的特征列表
        """
        normalized = []
        
        for i, feature in enumerate(features):
            feature_name = self.FEATURE_NAMES[i] if i < len(self. FEATURE_NAMES) else f'feature_{i}'
            
            min_val = self.min_values.get(feature_name, 0)
            max_val = self.max_values.get(feature_name, 1)
            
            if max_val == min_val:
                normalized_value = 0.5
            else:
                normalized_value = (feature - min_val) / (max_val - min_val)
                normalized_value = max(0.0, min(1.0, normalized_value))  # 确保在[0, 1]范围内
            
            normalized.append(normalized_value)
        
        return normalized
    
    def standardize_features(self, features:  List[float], mean: float = None, 
                            std: float = None) -> List[float]:
        """
        特征标准化（Z-score标准化）
        
        Args:
            features:  原始特征列表
            mean: 平均值（如果为None则自动计算）
            std: 标准差（如果为None则自动计算）
        
        Returns:
            标准化后的特征列表
        """
        if mean is None:
            mean = sum(features) / len(features) if features else 0
        
        if std is None: 
            variance = sum((x - mean) ** 2 for x in features) / len(features) if features else 1
            std = math.sqrt(variance)
        
        if std == 0:
            return features
        
        return [(x - mean) / std for x in features]
    
    def get_feature_importance(self) -> Dict[str, float]: 
        """
        获取特征重要性权重
        
        Returns: 
            特征重要性字典
        """
        # 基于异常检测的经验权重
        return {
            'packet_size':  0.15,
            'packet_rate':  0.20,
            'protocol_type':  0.10,
            'port_feature': 0.15,
            'ttl_feature': 0.10,
            'duration': 0.10,
            'entropy': 0.15,
            'direction_ratio':  0.05
        }
    
    def extract_batch(self, flows: List[Dict]) -> List[List[float]]: 
        """
        批量提取特征
        
        Args:
            flows: 流列表
        
        Returns: 
            特征向量矩阵
        """
        return [self.extract(flow) for flow in flows]