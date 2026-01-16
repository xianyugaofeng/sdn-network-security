"""
日志工具模块
提供统一的日志配置和管理
"""

import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path


class ColoredFormatter(logging.Formatter):
    """
    彩色日志格式化器
    """
    
    COLORS = {
        'DEBUG': '\033[36m',      # 青色
        'INFO': '\033[32m',       # 绿色
        'WARNING': '\033[33m',    # 黄色
        'ERROR': '\033[31m',      # 红色
        'CRITICAL': '\033[35m',   # 紫色
        'RESET': '\033[0m'        # 重置
    }
    
    def format(self, record):
        """
        格式化日志记录
        """
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        record.levelname = f"{log_color}{record.levelname}{reset}"
        
        return super().format(record)


class LoggerManager:
    """
    日志管理器
    """
    
    def __init__(self, log_dir: str = 'logs'):
        """
        初始化日志管理器
        
        Args:
            log_dir: 日志目录
        """
        self.log_dir = log_dir
        self.loggers = {}
        
        # 创建日志目录
        Path(log_dir).mkdir(exist_ok=True)
    
    def get_logger(self, name: str, level: int = logging.DEBUG) -> logging.Logger:
        """
        获取或创建日志记录器
        
        Args: 
            name: 日志记录器名称
            level:  日志级别
        
        Returns:
            日志记录器
        """
        if name in self.loggers:
            return self.loggers[name]
        
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # 避免重复添加handler
        if not logger.handlers:
            # 控制台handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            
            # 格式化器
            formatter = ColoredFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            
            # 文件handler
            log_file = os.path.join(self.log_dir, f'{name}.log')
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            file_handler.setLevel(level)
            
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        
        self.loggers[name] = logger
        return logger


# 全局日志管理器实例
_logger_manager = LoggerManager()


def setup_logger(name: str, filepath: str = None, 
                level: int = logging. DEBUG) -> logging.Logger:
    """
    设置日志记录器
    
    Args: 
        name: 日志记录器名称
        filepath: 日志文件路径（可选）
        level: 日志级别
    
    Returns:
        配置后的日志记录器
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 避免重复添加handler
    if logger.handlers:
        return logger
    
    # 创建格式化器
    formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 添加控制台handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 添加文件handler
    if filepath: 
        # 创建父目录
        os.makedirs(os.path. dirname(filepath), exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            filepath,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=10
        )
        file_handler.setLevel(level)
        
        file_formatter = logging. Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    获取日志记录器
    
    Args:
        name: 日志记录器名称
    
    Returns:
        日志记录器
    """
    return _logger_manager.get_logger(name)