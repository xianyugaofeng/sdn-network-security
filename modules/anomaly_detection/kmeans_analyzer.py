"""
基于K-means算法的异常检测模块
分析流量特征，识别异常行为
"""

import logging
from typing import Dict, List, Tuple
from collections import defaultdict
import math
from datetime import datetime

logger = logging.getLogger(__name__)


class KMeansAnalyzer:
    """
    K-means异常检测分析器
    """
    
    def __init__(self, k_clusters: int = 3, max_iterations: int = 100):
        """
        初始化K-means分析器
        
        Args: 
            k_clusters: 聚类数量
            max_iterations: 最大迭代次数
        """
        self.k = k_clusters
        self.max_iterations = max_iterations
        self.centroids = []
        self.clusters = [[] for _ in range(k_clusters)]
        self.feature_extractor = FeatureExtractor()
    
    def detect(self, flows: List[Dict]) -> List[Dict]:
        """
        检测异常流
        
        Args:
            flows: 流列表
        
        Returns: 
            异常流列表
        """
        if len(flows) < self.k:
            return []
        
        # 提取特征向量
        feature_vectors = []
        for flow in flows:
            features = self.feature_extractor.extract(flow)
            feature_vectors. append((features, flow))
        
        # 初始化质心
        if not self.centroids:
            self._initialize_centroids(feature_vectors)
        
        # 执行K-means聚类
        self._kmeans_clustering(feature_vectors)
        
        # 识别异常点
        anomalies = self._identify_anomalies(feature_vectors)
        
        return anomalies
    
    def _initialize_centroids(self, feature_vectors: List[Tuple]):
        """
        初始化质心
        """
        import random
        
        # 随机选择k个点作为初始质心
        sample = random.sample(feature_vectors, min(self.k, len(feature_vectors)))
        self.centroids = [features for features, _ in sample]
        
        logger.info(f"Initialized {len(self.centroids)} centroids")
    
    def _kmeans_clustering(self, feature_vectors: List[Tuple]):
        """
        执行K-means聚类
        """
        for iteration in range(self.max_iterations):
            # 清空聚类
            self.clusters = [[] for _ in range(self.k)]
            
            # 分配点到最近的质心
            for features, flow in feature_vectors: 
                cluster_idx = self._find_nearest_centroid(features)
                self. clusters[cluster_idx].append((features, flow))
            
            # 计算新的质心
            new_centroids = []
            for cluster in self.clusters:
                if cluster:
                    new_centroid = self._calculate_centroid(cluster)
                    new_centroids.append(new_centroid)
                else:
                    new_centroids.append(self. centroids[len(new_centroids)])
            
            # 检查收敛
            if self._centroids_converged(self.centroids, new_centroids):
                logger.info(f"K-means converged at iteration {iteration}")
                break
            
            self.centroids = new_centroids
    
    def _find_nearest_centroid(self, features: List[float]) -> int:
        """
        找到最近的质心
        """
        min_distance = float('inf')
        nearest_idx = 0
        
        for idx, centroid in enumerate(self. centroids):
            distance = self._euclidean_distance(features, centroid)
            if distance < min_distance:
                min_distance = distance
                nearest_idx = idx
        
        return nearest_idx
    
    def _calculate_centroid(self, cluster: List[Tuple]) -> List[float]:
        """
        计算聚类的质心
        """
        if not cluster:
            return [0] * len(cluster[0][0]) if cluster else [0] * 5
        
        num_features = len(cluster[0][0])
        centroid = [0] * num_features
        
        for features, _ in cluster:
            for i, val in enumerate(features):
                centroid[i] += val
        
        for i in range(num_features):
            centroid[i] /= len(cluster)
        
        return centroid
    
    def _centroids_converged(self, old_centroids: List, new_centroids: List) -> bool:
        """
        检查质心是否收敛
        """
        threshold = 0.001
        
        for old, new in zip(old_centroids, new_centroids):
            distance = self._euclidean_distance(old, new)
            if distance > threshold:
                return False
        
        return True
    
    def _euclidean_distance(self, point1: List[float], point2: List[float]) -> float:
        """
        计算欧几里得距离
        """
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(point1, point2)))
    
    def _identify_anomalies(self, feature_vectors: List[Tuple]) -> List[Dict]:
        """
        识别异常点
        """
        anomalies = []
        
        # 计算每个聚类的平均距离和标准差
        cluster_stats = []
        for cluster in self.clusters:
            if not cluster:
                cluster_stats.append({'mean': 0, 'std': 0})
                continue
            
            distances = []
            centroid_idx = len(cluster_stats)
            centroid = self.centroids[centroid_idx]
            
            for features, _ in cluster:
                dist = self._euclidean_distance(features, centroid)
                distances.append(dist)
            
            mean_dist = sum(distances) / len(distances) if distances else 0
            variance = sum((d - mean_dist) ** 2 for d in distances) / len(distances) \
                if distances else 0
            std_dist = math.sqrt(variance)
            
            cluster_stats.append({'mean': mean_dist, 'std': std_dist})
        
        # 识别离群点（距离大于均值+3*标准差）
        for cluster_idx, cluster in enumerate(self.clusters):
            stats = cluster_stats[cluster_idx]
            threshold = stats['mean'] + 3 * stats['std']
            
            for features, flow in cluster:
                distance = self._euclidean_distance(features, self.centroids[cluster_idx])
                
                if distance > threshold:
                    anomalies.append({
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'MEDIUM',
                        'type': 'ANOMALY_DETECTED',
                        'anomaly_score': distance,
                        'threshold': threshold,
                        'flow_info': {
                            'src_ip': flow.get('ip_src'),
                            'dst_ip':  flow.get('ip_dst'),
                            'protocol': flow.get('protocol'),
                            'bytes':  flow.get('packet_length')
                        }
                    })
        
        logger.info(f"Detected {len(anomalies)} anomalous flows")
        return anomalies


class FeatureExtractor: 
    """
    特征提取器
    """
    
    def extract(self, flow: Dict) -> List[float]:
        """
        从流中提取特征向量
        
        Args: 
            flow: 流信息字典
        
        Returns: 
            特征向量列表
        """
        features = [
            self._extract_packet_size(flow),
            self._extract_packet_rate(flow),
            self._extract_protocol_feature(flow),
            self._extract_port_feature(flow),
            self._extract_ttl_feature(flow)
        ]
        
        # 归一化
        features = self._normalize(features)
        
        return features
    
    def _extract_packet_size(self, flow:  Dict) -> float:
        """
        提取数据包大小特征
        """
        return float(flow.get('packet_length', 0)) / 10000.0  # 归一化
    
    def _extract_packet_rate(self, flow: Dict) -> float:
        """
        提取数据包速率特征
        """
        # 简化实现，实际应统计时间窗口内的包数
        return 1.0
    
    def _extract_protocol_feature(self, flow: Dict) -> float:
        """
        提取协议特征
        """
        protocol = flow. get('protocol', 'UNKNOWN')
        protocol_map = {'TCP': 0. 3, 'UDP': 0.6, 'ICMP': 0.9, 'OTHER': 0.0}
        return protocol_map. get(protocol, 0.0)
    
    def _extract_port_feature(self, flow: Dict) -> float:
        """
        提取端口特征
        """
        dst_port = flow.get('tp_dst', 0)
        if dst_port < 1024: 
            return 0.2  # 特权端口
        elif dst_port < 49152:
            return 0.5  # 注册端口
        else: 
            return 0.8  # 动态端口
    
    def _extract_ttl_feature(self, flow: Dict) -> float:
        """
        提取TTL特征
        """
        ttl = flow.get('ttl', 64)
        return float(ttl) / 255.0  # 归一化
    
    def _normalize(self, features: List[float]) -> List[float]:
        """
        特征归一化
        """
        # Min-Max归一化到[0, 1]
        min_val = min(features) if features else 0
        max_val = max(features) if features else 1
        
        if max_val == min_val:
            return [0.5] * len(features)
        
        return [(f - min_val) / (max_val - min_val) for f in features]