"""
工具模块 (Utilities Module)

提供日志、数据库、网络等工具函数：
- logger: 日志管理
- db_helper: 数据库助手
- network_utils: 网络工具

使用示例:
    from utils.logger import setup_logger
    from utils.db_helper import DatabaseHelper
    from utils.network_utils import NetworkUtils
    
    logger = setup_logger('MyApp')
    db = DatabaseHelper()
    
    if NetworkUtils.is_valid_ip('192.168.1.1'):
        print("Valid IP")
"""

from .logger import setup_logger, get_logger, LoggerManager, ColoredFormatter
from .db_helper import DatabaseHelper
from .network_utils import NetworkUtils

__all__ = [
    'setup_logger',
    'get_logger',
    'LoggerManager',
    'ColoredFormatter',
    'DatabaseHelper',
    'NetworkUtils'
]

__version__ = '1.0.0'
__doc__ = """
工具模块
========

包含以下子模块：

1. logger (日志工具)
   - setup_logger: 设置日志记录器
   - get_logger: 获取日志记录器
   - LoggerManager: 日志管理器
   - ColoredFormatter: 彩色日志格式化器

2. db_helper (数据库工具)
   - DatabaseHelper:  SQLite数据库助手
   - 支持流记录、告警、规则等表

3. network_utils (网络工具)
   - NetworkUtils: 网络工具类
   - IP/MAC/端口验证
   - 地址转换等功能

示例代码：
--------
from utils import setup_logger, DatabaseHelper, NetworkUtils

# 日志配置
logger = setup_logger('SDNApp', 'logs/app.log')
logger.info("Application started")

# 数据库操作
db = DatabaseHelper('data/security.db')
db.insert_flow_record({
    'src_ip': '192.168.1.1',
    'dst_ip': '192.168.1.2',
    'protocol': 'TCP',
    'packet_count': 100,
    'byte_count': 5000
})

# 网络验证
if NetworkUtils.is_valid_ip('192.168.1.1'):
    print("Valid IP address")

if NetworkUtils.is_valid_port(8080):
    print("Valid port number")
"""