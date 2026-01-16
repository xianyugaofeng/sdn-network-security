"""
流表管理器
提供流表的CRUD操作和管理功能
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class FlowManager:
    """
    流表管理器
    """
    
    def __init__(self):
        """
        初始化流表管理器
        """
        self.flows = {}  # {flow_id: flow_info}
        self.flow_counter = 0
    
    def add_flow(self, datapath_id: int, match:  Dict, actions: List, 
                 priority: int = 0, idle_timeout: int = 0) -> int:
        """
        添加流表项
        
        Args:
            datapath_id: 交换机ID
            match: 匹配条件
            actions: 动作列表
            priority: 优先级
            idle_timeout: 空闲超时
        
        Returns:
            流ID
        """
        flow_id = self.flow_counter
        self.flow_counter += 1
        
        flow_info = {
            'id': flow_id,
            'datapath_id': datapath_id,
            'match': match,
            'actions': actions,
            'priority': priority,
            'idle_timeout': idle_timeout,
            'created_at': datetime.now().isoformat(),
            'packet_count': 0,
            'byte_count': 0
        }
        
        self. flows[flow_id] = flow_info
        logger.info(f"Flow {flow_id} added to switch {datapath_id}")
        
        return flow_id
    
    def remove_flow(self, flow_id: int) -> bool:
        """
        删除流表项
        
        Args:
            flow_id: 流ID
        
        Returns:
            True:  删除成功
        """
        if flow_id in self.flows:
            del self.flows[flow_id]
            logger.info(f"Flow {flow_id} removed")
            return True
        return False
    
    def get_flow(self, flow_id: int) -> Optional[Dict]:
        """
        获取流表项
        
        Args: 
            flow_id: 流ID
        
        Returns: 
            流信息字典
        """
        return self.flows.get(flow_id)
    
    def list_flows(self, datapath_id: Optional[int] = None) -> List[Dict]:
        """
        列出流表项
        
        Args: 
            datapath_id: 交换机ID（可选）
        
        Returns:
            流列表
        """
        if datapath_id is None:
            return list(self.flows.values())
        
        return [f for f in self.flows.values() 
                if f['datapath_id'] == datapath_id]
    
    def update_flow_stats(self, flow_id: int, packet_count: int, byte_count: int):
        """
        更新流统计信息
        
        Args:
            flow_id: 流ID
            packet_count:  包数量
            byte_count: 字节数量
        """
        if flow_id in self.flows:
            self.flows[flow_id]['packet_count'] = packet_count
            self.flows[flow_id]['byte_count'] = byte_count
    
    def get_statistics(self) -> Dict:
        """
        获取管理器统计信息
        """
        total_packets = sum(f['packet_count'] for f in self.flows.values())
        total_bytes = sum(f['byte_count'] for f in self.flows.values())
        
        return {
            'total_flows': len(self. flows),
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'timestamp': datetime.now().isoformat()
        }