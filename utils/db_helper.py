"""
数据库辅助模块
提供数据库操作的抽象接口
"""

import logging
import sqlite3
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class DatabaseHelper:
    """
    数据库助手类（基于SQLite）
    """
    
    def __init__(self, db_path: str = 'data/sdn_security.db'):
        """
        初始化数据库助手
        
        Args:
            db_path: 数据库文件路径
        """
        self.db_path = db_path
        
        # 创建数据目录
        Path(db_path).parent.mkdir(exist_ok=True)
        
        self. conn = None
        self.cursor = None
        
        self._initialize_database()
    
    def _initialize_database(self):
        """
        初始化数据库（创建表）
        """
        try:  
            self.connect()
            self._create_tables()
            logger.  info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
    
    def connect(self):
        """
        连接数据库
        """
        try:
            self.  conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn. row_factory = sqlite3.Row
            self.cursor = self. conn.cursor()
            logger. debug("Database connection established")
        except Exception as e:
            logger.  error(f"Error connecting to database: {e}")
            raise
    
    def disconnect(self):
        """
        断开数据库连接
        """
        try:
            if self.conn:
                self.conn.close()
                logger.debug("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database:   {e}")
    
    def _create_tables(self):
        """
        创建数据库表
        """
        try: 
            # 流量记录表
            self.cursor. execute('''
                CREATE TABLE IF NOT EXISTS flow_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    packet_count INTEGER DEFAULT 0,
                    byte_count INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 创建索引以加速查询
            self.cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_flow_timestamp 
                ON flow_records(timestamp)
            ''')
            
            # 入侵告警表
            self.cursor. execute('''
                CREATE TABLE IF NOT EXISTS intrusion_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    protocol TEXT,
                    alert_type TEXT,
                    severity TEXT,
                    description TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alert_timestamp 
                ON intrusion_alerts(timestamp)
            ''')
            
            # 异常检测表
            self. cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomaly_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    anomaly_type TEXT,
                    severity TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    anomaly_score REAL,
                    details TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_anomaly_timestamp 
                ON anomaly_alerts(timestamp)
            ''')
            
            # 防火墙规则表
            self.cursor. execute('''
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    action TEXT,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    priority INTEGER,
                    created_at TEXT,
                    updated_at TEXT
                )
            ''')
            
            # 会话表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    start_time TEXT,
                    end_time TEXT,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    status TEXT DEFAULT 'ACTIVE'
                )
            ''')
            
            # 性能指标表
            self.cursor. execute('''
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    timestamp TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 系统事件日志表
            self.cursor. execute('''
                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    event_message TEXT,
                    severity TEXT,
                    timestamp TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.conn.commit()
            logger.debug("All database tables created successfully")
        except Exception as e:
            logger. error(f"Error creating tables:  {e}")
    
    def insert_flow_record(self, flow_data: Dict) -> bool:
        """
        插入流记录
        
        Args:  
            flow_data: 流数据字典
        
        Returns:
            True: 插入成功
        """
        try:
            sql = '''
                INSERT INTO flow_records 
                (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_count, byte_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            '''
            
            values = (
                flow_data.  get('timestamp', datetime.now().isoformat()),
                flow_data.get('src_ip'),
                flow_data.get('dst_ip'),
                flow_data.get('protocol'),
                flow_data.get('src_port'),
                flow_data.  get('dst_port'),
                flow_data.get('packet_count', 1),
                flow_data.get('byte_count', 0)
            )
            
            self.cursor.execute(sql, values)
            self.conn.commit()
            return True
        except Exception as e:  
            logger.error(f"Error inserting flow record: {e}")
            return False
    
    def insert_intrusion_alert(self, alert_data: Dict) -> bool:
        """
        插入入侵告警
        
        Args:
            alert_data:   告警数据字典
        
        Returns:
            True:  插入成功
        """
        try:
            sql = '''
                INSERT INTO intrusion_alerts
                (timestamp, source_ip, dest_ip, protocol, alert_type, severity, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            '''
            
            values = (
                alert_data.get('timestamp', datetime.now().isoformat()),
                alert_data.get('source_ip'),
                alert_data.get('dest_ip'),
                alert_data.get('protocol'),
                alert_data.get('alert_type', 'UNKNOWN'),
                alert_data.get('severity', 'MEDIUM'),
                alert_data.get('description', '')
            )
            
            self.cursor.execute(sql, values)
            self.conn. commit()
            logger.info(f"Intrusion alert recorded: {alert_data.  get('source_ip')}")
            return True
        except Exception as e:  
            logger.error(f"Error inserting intrusion alert:  {e}")
            return False
    
    def insert_anomaly_alert(self, anomalies: List[Dict]) -> bool:
        """
        插入异常告警
        
        Args:
            anomalies:  异常列表
        
        Returns:  
            True: 插入成功
        """
        try:  
            sql = '''
                INSERT INTO anomaly_alerts
                (timestamp, anomaly_type, severity, src_ip, dst_ip, anomaly_score, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            '''
            
            for anomaly in anomalies:  
                values = (
                    anomaly.get('timestamp', datetime.  now().isoformat()),
                    anomaly.get('type', 'UNKNOWN'),
                    anomaly.get('severity', 'MEDIUM'),
                    anomaly.get('flow_info', {}).get('src_ip'),
                    anomaly.get('flow_info', {}).get('dst_ip'),
                    anomaly.get('anomaly_score', 0.0),
                    json.dumps(anomaly)
                )
                
                self.cursor.execute(sql, values)
            
            self.conn.commit()
            logger.info(f"Recorded {len(anomalies)} anomaly alerts")
            return True
        except Exception as e: 
            logger.error(f"Error inserting anomaly alerts: {e}")
            return False
    
    def insert_firewall_rule(self, rule:   Dict) -> bool:
        """
        插入防火墙规则
        
        Args:  
            rule: 规则字典
        
        Returns: 
            True: 插入成功
        """
        try:  
            sql = '''
                INSERT OR REPLACE INTO firewall_rules
                (id, name, action, protocol, src_ip, dst_ip, src_port, dst_port, priority, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            '''
            
            values = (
                rule.  get('id'),
                rule.  get('name'),
                rule.  get('action'),
                rule.  get('protocol'),
                rule.  get('ip_src'),
                rule. get('ip_dst'),
                rule.get('tp_src'),
                rule.get('tp_dst'),
                rule.get('priority', 0),
                rule.get('created_at', datetime.now().isoformat()),
                datetime.now().isoformat()
            )
            
            self.  cursor.execute(sql, values)
            self.conn.commit()
            return True
        except Exception as e:  
            logger.error(f"Error inserting firewall rule:  {e}")
            return False
    
    def insert_session(self, session_data: Dict) -> bool:
        """
        插入会话记录
        
        Args: 
            session_data: 会话数据字典
        
        Returns:  
            True: 插入成功
        """
        try: 
            sql = '''
                INSERT INTO sessions
                (src_ip, dst_ip, protocol, src_port, dst_port, start_time, end_time, packet_count, byte_count, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            '''
            
            values = (
                session_data.get('src_ip'),
                session_data.get('dst_ip'),
                session_data.get('protocol'),
                session_data.get('src_port'),
                session_data.get('dst_port'),
                session_data.get('start_time', datetime.now().isoformat()),
                session_data.get('end_time'),
                session_data.get('packet_count', 0),
                session_data.get('byte_count', 0),
                session_data.get('status', 'ACTIVE')
            )
            
            self.cursor. execute(sql, values)
            self.conn.commit()
            return True
        except Exception as e: 
            logger.error(f"Error inserting session: {e}")
            return False
    
    def record_metric(self, metric_name: str, metric_value: float) -> bool:
        """
        记录性能指标
        
        Args:
            metric_name: 指标名称
            metric_value: 指标值
        
        Returns: 
            True: 记录成功
        """
        try:
            sql = '''
                INSERT INTO performance_metrics
                (metric_name, metric_value, timestamp)
                VALUES (?, ?, ?)
            '''
            
            values = (metric_name, metric_value, datetime.now().isoformat())
            self.cursor.execute(sql, values)
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error recording metric: {e}")
            return False
    
    def record_system_event(self, event_type: str, message: str, severity: str = 'INFO') -> bool:
        """
        记录系统事件
        
        Args:
            event_type: 事件类型
            message: 事件消息
            severity: 严重程度
        
        Returns:  
            True: 记录成功
        """
        try:
            sql = '''
                INSERT INTO system_events
                (event_type, event_message, severity, timestamp)
                VALUES (?, ?, ?, ?)
            '''
            
            values = (event_type, message, severity, datetime.now().isoformat())
            self.cursor.execute(sql, values)
            self.conn.commit()
            return True
        except Exception as e: 
            logger.error(f"Error recording system event: {e}")
            return False
    
    def query_intrusion_alerts(self, limit: int = 100, 
                              hours:   int = 24) -> List[Dict]:
        """
        查询入侵告警
        
        Args:
            limit:   返回数量限制
            hours:  时间范围（小时）
        
        Returns:  
            告警列表
        """
        try:
            sql = '''
                SELECT * FROM intrusion_alerts
                WHERE timestamp > datetime('now', '-' || ? || ' hours')
                ORDER BY timestamp DESC
                LIMIT ?
            '''
            
            self.cursor.execute(sql, (hours, limit))
            rows = self.cursor.fetchall()
            
            return [dict(row) for row in rows]
        except Exception as e:  
            logger.error(f"Error querying intrusion alerts:  {e}")
            return []
    
    def query_anomaly_alerts(self, limit: int = 100) -> List[Dict]:
        """
        查询异常告警
        
        Args:
            limit: 返回数量限制
        
        Returns: 
            告警列表
        """
        try:  
            sql = '''
                SELECT * FROM anomaly_alerts
                ORDER BY timestamp DESC
                LIMIT ?  
            '''
            
            self.cursor.execute(sql, (limit,))
            rows = self.cursor.fetchall()
            
            return [dict(row) for row in rows]
        except Exception as e: 
            logger.  error(f"Error querying anomaly alerts: {e}")
            return []
    
    def query_flow_records(self, src_ip: str = None, dst_ip: str = None,
                          limit: int = 100) -> List[Dict]:
        """
        查询流记录
        
        Args:
            src_ip: 源IP（可选）
            dst_ip: 目标IP（可选）
            limit: 返回数量限制
        
        Returns:  
            流记录列表
        """
        try: 
            sql = 'SELECT * FROM flow_records WHERE 1=1'
            params = []
            
            if src_ip:
                sql += ' AND src_ip = ?'
                params.append(src_ip)
            
            if dst_ip:
                sql += ' AND dst_ip = ?'
                params.append(dst_ip)
            
            sql += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            self.cursor.execute(sql, params)
            rows = self.cursor.fetchall()
            
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error querying flow records: {e}")
            return []
    
    def get_flow_statistics(self, hours: int = 24) -> Dict:
        """
        获取流统计信息
        
        Args:
            hours: 时间范围（小时）
        
        Returns:
            统计字典
        """
        try:  
            sql = '''
                SELECT protocol, COUNT(*) as count, SUM(byte_count) as total_bytes
                FROM flow_records
                WHERE timestamp > datetime('now', '-' || ? || ' hours')
                GROUP BY protocol
            '''
            
            self.cursor.execute(sql, (hours,))
            rows = self.cursor.fetchall()
            
            return {row['protocol']: {
                'count': row['count'],
                'total_bytes':   row['total_bytes']
            } for row in rows}
        except Exception as e:
            logger.error(f"Error getting flow statistics: {e}")
            return {}
    
    def get_alert_statistics(self, hours: int = 24) -> Dict:
        """
        获取告警统计
        
        Args:
            hours: 时间范围（小时）
        
        Returns: 
            统计字典
        """
        try: 
            sql = '''
                SELECT severity, COUNT(*) as count
                FROM intrusion_alerts
                WHERE timestamp > datetime('now', '-' || ? || ' hours')
                GROUP BY severity
            '''
            
            self.cursor.execute(sql, (hours,))
            rows = self.cursor.fetchall()
            
            return {row['severity']: row['count'] for row in rows}
        except Exception as e:
            logger.error(f"Error getting alert statistics: {e}")
            return {}
    
    def cleanup_old_data(self, days: int = 30) -> bool:
        """
        清理旧数据
        
        Args:
            days: 保留天数
        
        Returns: 
            True: 清理成功
        """
        try: 
            # 清理旧流记录
            self.cursor.execute(
                "DELETE FROM flow_records WHERE timestamp < datetime('now', '-' || ?   || ' days')",
                (days,)
            )
            
            # 清理旧告警
            self.cursor.execute(
                "DELETE FROM intrusion_alerts WHERE timestamp < datetime('now', '-' || ?  || ' days')",
                (days,)
            )
            
            # 清理旧异常
            self.cursor.execute(
                "DELETE FROM anomaly_alerts WHERE timestamp < datetime('now', '-' || ? || ' days')",
                (days,)
            )
            
            self.conn.commit()
            logger.info(f"Cleaned up data older than {days} days")
            return True
        except Exception as e:
            logger.error(f"Error cleaning up data: {e}")
            return False
    
    def get_database_info(self) -> Dict:
        """
        获取数据库信息
        
        Returns:  
            数据库信息字典
        """
        try: 
            info = {}
            
            # 统计各表的记录数
            tables = [
                'flow_records',
                'intrusion_alerts',
                'anomaly_alerts',
                'firewall_rules',
                'sessions'
            ]
            
            for table in tables:
                self.cursor.execute(f'SELECT COUNT(*) FROM {table}')
                count = self.cursor.fetchone()[0]
                info[table] = count
            
            info['database_path'] = self.db_path
            info['last_update'] = datetime.now().isoformat()
            
            return info
        except Exception as e: 
            logger.error(f"Error getting database info: {e}")
            return {}