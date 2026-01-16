"""
异常检测模块单元测试
"""

import unittest
from modules.anomaly_detection import FeatureExtractor, KMeansAnalyzer


class TestFeatureExtractor(unittest.TestCase):
    """
    特征提取器测试
    """
    
    def setUp(self):
        """
        设置测试环境
        """
        self.extractor = FeatureExtractor()
    
    def test_extract_features(self):
        """
        测试提取特征
        """
        flow = {
            'packet_length': 1500,
            'protocol': 'TCP',
            'tp_dst': 80,
            'ttl': 64
        }
        
        features = self.extractor.extract(flow)
        
        self. assertEqual(len(features), 8)
        # 检查特征都在[0, 1]范围内
        for feature in features:
            self.assertGreaterEqual(feature, 0.0)
            self.assertLessEqual(feature, 1.0)
    
    def test_extract_packet_size_feature(self):
        """
        测试提取数据包大小特征
        """
        flow = {'packet_length': 1500}
        
        feature = self.extractor.extract_packet_size(flow)
        
        self. assertIsInstance(feature, float)
        self.assertGreaterEqual(feature, 0.0)
    
    def test_extract_protocol_feature(self):
        """
        测试提取协议特征
        """
        tcp_flow = {'protocol': 'TCP'}
        udp_flow = {'protocol': 'UDP'}
        icmp_flow = {'protocol': 'ICMP'}
        
        tcp_feature = self.extractor.extract_protocol_feature(tcp_flow)
        udp_feature = self.extractor.extract_protocol_feature(udp_flow)
        icmp_feature = self.extractor.extract_protocol_feature(icmp_flow)
        
        # 检查不同协议有不同的特征值
        self.assertNotEqual(tcp_feature, udp_feature)
        self.assertNotEqual(udp_feature, icmp_feature)
    
    def test_normalize_features(self):
        """
        测试特征归一化
        """
        features = [100, 50, 25, 10]
        
        normalized = self.extractor. normalize_features(features)
        
        self.assertEqual(len(normalized), len(features))
        for feature in normalized:
            self.assertGreaterEqual(feature, 0.0)
            self.assertLessEqual(feature, 1.0)
    
    def test_extract_batch(self):
        """
        测试批量提取特征
        """
        flows = [
            {'packet_length':  1500, 'protocol': 'TCP', 'ttl': 64},
            {'packet_length': 1000, 'protocol': 'UDP', 'ttl': 128},
            {'packet_length':  500, 'protocol': 'ICMP', 'ttl': 255}
        ]
        
        features_matrix = self.extractor.extract_batch(flows)
        
        self.assertEqual(len(features_matrix), 3)
        for features in features_matrix:
            self.assertEqual(len(features), 8)


class TestKMeansAnalyzer(unittest.TestCase):
    """
    K-means异常检测测试
    """
    
    def setUp(self):
        """
        设置测试环境
        """
        self.analyzer = KMeansAnalyzer(k_clusters=3, max_iterations=100)
    
    def test_initialization(self):
        """
        测试初始化
        """
        self.assertEqual(self.analyzer.k, 3)
        self.assertEqual(self.analyzer.max_iterations, 100)
    
    def test_detect_empty_flows(self):
        """
        测试检测空流列表
        """
        flows = []
        
        anomalies = self.analyzer.detect(flows)
        
        self.assertEqual(len(anomalies), 0)
    
    def test_detect_normal_flows(self):
        """
        测试检测正常流
        """
        flows = [
            {
                'packet_length': 1500,
                'protocol':  'TCP',
                'tp_dst': 80,
                'ttl': 64
            }
            for _ in range(10)
        ]
        
        anomalies = self.analyzer.detect(flows)
        
        # 正常流不应该被检测为异常
    
    def test_euclidean_distance(self):
        """
        测试欧几里得距离计算
        """
        p1 = [0, 0, 0]
        p2 = [3, 4, 0]
        
        distance = self.analyzer._euclidean_distance(p1, p2)
        
        self.assertAlmostEqual(distance, 5.0)


class TestAnomalyDetectionIntegration(unittest.TestCase):
    """
    异常检测集成测试
    """
    
    def setUp(self):
        """
        设置测试环境
        """
        self.extractor = FeatureExtractor()
        self.analyzer = KMeansAnalyzer(k_clusters=3)
    
    def test_feature_extraction_to_clustering(self):
        """
        测试从特征提取到聚类的完整流程
        """
        flows = [
            {
                'packet_length': 1500,
                'protocol': 'TCP',
                'tp_dst': 80,
                'ttl': 64
            }
            for _ in range(20)
        ]
        
        # 提取特征
        features = self.extractor.extract_batch(flows)
        
        self.assertEqual(len(features), 20)
        
        # 检测异常
        anomalies = self.analyzer.detect(flows)


if __name__ == '__main__':
    unittest.main()