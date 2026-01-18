# -*- coding: utf-8 -*-
"""
数据库辅助模块 - Python 3.6 兼容版本
"""

from __future__ import print_function
import logging
import json
import os
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import sqlite3, make it optional
try:
    import sqlite3
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False
    logger.warning('SQLite3 is not available. Database operations will be disabled.')


class DatabaseHelper(object):
    """
    数据库助手类（基于 SQLite）
    """

    def __init__(self, db_path='data/sdn_security.db'):
        """
        初始化数据库助手

        Args:
            db_path: 数据库文件路径
        """
        self.db_path = db_path
        self.sqlite_available = SQLITE_AVAILABLE

        if not self.sqlite_available:
            logger.warning('SQLite3 is not available. DatabaseHelper initialized in no-op mode.')
            self.conn = None
            self.cursor = None
            return

        # 创建数据目录
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)

        self.conn = None
        self.cursor = None

        self._initialize_database()

    def _initialize_database(self):
        """
        初始化数据库（创建表）
        """
        if not self.sqlite_available:
            return
        
        try:
            self.connect()
            self._create_tables()
            logger.info('Database initialized successfully')
        except Exception as e:
            logger.error('Error initializing database: %s', str(e))

    def connect(self):
        """
        连接数据库
        """
        try: 
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self.cursor = self.conn.cursor()
            logger.debug('Database connection established')
        except Exception as e:
            logger.error('Error connecting to database: %s', str(e))
            raise

    def disconnect(self):
        """
        断开数据库连接
        """
        try:
            if self.conn:
                self.conn.close()
                logger.debug('Database connection closed')
        except Exception as e:
            logger.error('Error closing database:  %s', str(e))

    def _create_tables(self):
        """
        创建数据库表
        """
        try: 
            # 流量记录表
            self.cursor.execute('''
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

            # 创建索引
            self.cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_flow_timestamp 
                ON flow_records(timestamp)
            ''')

            # 入侵告警表
            self.cursor.execute('''
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
            self.cursor.execute('''
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
            self.cursor.execute('''
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

            self.conn.commit()
            logger.debug('All database tables created successfully')
        except Exception as e:
            logger.error('Error creating tables: %s', str(e))

    def insert_flow_record(self, flow_data):
        """
        插入流记录

        Args:
            flow_data: 流数据字典

        Returns:
            True:  插入成功
        """
        if not self.sqlite_available:
            return False
        
        try:
            sql = '''
                INSERT INTO flow_records 
                (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_count, byte_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            '''

            values = (
                flow_data.get('timestamp', datetime.now().isoformat()),
                flow_data.get('src_ip'),
                flow_data.get('dst_ip'),
                flow_data.get('protocol'),
                flow_data.get('src_port'),
                flow_data.get('dst_port'),
                flow_data.get('packet_count', 1),
                flow_data.get('byte_count', 0)
            )

            self.cursor.execute(sql, values)
            self.conn.commit()
            return True
        except Exception as e: 
            logger.error('Error inserting flow record: %s', str(e))
            return False

    def insert_intrusion_alert(self, alert_data):
        """
        插入入侵告警

        Args:
            alert_data: 告警数据字典

        Returns:
            True: 插入成功
        """
        if not self.sqlite_available:
            return False
        
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
            self.conn.commit()
            logger.info('Intrusion alert recorded: %s', alert_data.get('source_ip'))
            return True
        except Exception as e:
            logger.error('Error inserting intrusion alert: %s', str(e))
            return False

    def insert_anomaly_alert(self, anomalies):
        """
        插入异常告警

        Args:
            anomalies: 异常列表

        Returns:
            True: 插入成功
        """
        if not self.sqlite_available:
            return False
        
        try:
            sql = '''
                INSERT INTO anomaly_alerts
                (timestamp, anomaly_type, severity, src_ip, dst_ip, anomaly_score, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            '''

            for anomaly in anomalies: 
                values = (
                    anomaly.get('timestamp', datetime.now().isoformat()),
                    anomaly.get('type', 'UNKNOWN'),
                    anomaly.get('severity', 'MEDIUM'),
                    anomaly.get('flow_info', {}).get('src_ip'),
                    anomaly.get('flow_info', {}).get('dst_ip'),
                    anomaly.get('anomaly_score', 0.0),
                    json.dumps(anomaly)
                )

                self.cursor.execute(sql, values)

            self.conn.commit()
            logger.info('Recorded %d anomaly alerts', len(anomalies))
            return True
        except Exception as e:
            logger.error('Error inserting anomaly alerts: %s', str(e))
            return False

    def get_database_info(self):
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
                self.cursor.execute('SELECT COUNT(*) FROM {0}'.format(table))
                count = self.cursor.fetchone()[0]
                info[table] = count

            info['database_path'] = self.db_path
            info['last_update'] = datetime.now().isoformat()

            return info
        except Exception as e:
            logger.error('Error getting database info: %s', str(e))
            return {}

    def cleanup_old_data(self, days=30):
        """
        清理旧数据

        Args: 
            days: 保留天数

        Returns:
            True: 清理成功
        """
        try:
            self.cursor.execute(
                "DELETE FROM flow_records WHERE timestamp < datetime('now', '-' || ? || ' days')",
                (days,)
            )

            self.cursor.execute(
                "DELETE FROM intrusion_alerts WHERE timestamp < datetime('now', '-' || ? || ' days')",
                (days,)
            )

            self.conn.commit()
            logger.info('Cleaned up data older than %d days', days)
            return True
        except Exception as e: 
            logger.error('Error cleaning up data: %s', str(e))
            return False