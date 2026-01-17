# -*- coding: utf-8 -*-
"""
日志工具模块 - Python 3.6 兼容版本
"""

from __future__ import print_function
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
        'DEBUG':  '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
        'RESET': '\033[0m'
    }

    def format(self, record):
        """
        格式化日志记录
        """
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']

        record.levelname = '{0}{1}{2}'.format(log_color, record.levelname, reset)

        return logging.Formatter.format(self, record)


class LoggerManager(object):
    """
    日志管理器
    """

    def __init__(self, log_dir='logs'):
        """
        初始化日志管理器

        Args:
            log_dir:  日志目录
        """
        self.log_dir = log_dir
        self.loggers = {}

        # 创建日志目录
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

    def get_logger(self, name, level=logging.DEBUG):
        """
        获取或创建日志记录器

        Args:
            name: 日志记录器名称
            level: 日志级别

        Returns:
            日志记录器
        """
        if name in self.loggers:
            return self.loggers[name]

        logger = logging.getLogger(name)
        logger.setLevel(level)

        # 避免重复添加 handler
        if not logger.handlers:
            # 控制台 handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)

            # 格式化器
            formatter = ColoredFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

            # 文件 handler
            log_file = os.path.join(self. log_dir, '{0}.log'.format(name))
            file_handler = logging. handlers.RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,
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


def setup_logger(name, filepath=None, level=logging.DEBUG):
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

    # 避免重复添加 handler
    if logger.handlers:
        return logger

    # 创建格式化器
    formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 添加控制台 handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler. setFormatter(formatter)
    logger.addHandler(console_handler)

    # 添加文件 handler
    if filepath:
        # 创建父目录
        filepath_dir = os.path.dirname(filepath)
        if filepath_dir and not os.path.exists(filepath_dir):
            os.makedirs(filepath_dir)

        file_handler = logging.handlers.RotatingFileHandler(
            filepath,
            maxBytes=10*1024*1024,
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


def get_logger(name):
    """
    获取日志记录器

    Args:
        name: 日志记录器名称

    Returns:
        日志记录器
    """
    return _logger_manager.get_logger(name)