# -*- coding: utf-8 -*-
"""
Windows兼容性工具模块
提供Windows平台特定的功能和兼容性处理
"""

from __future__ import print_function
import os
import sys
import platform
import logging

logger = logging.getLogger(__name__)

# 检测操作系统
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MAC = platform.system() == 'Darwin'


def get_os_type():
    """
    获取操作系统类型
    
    Returns:
        str: 'windows', 'linux', 'mac', 或 'unknown'
    """
    if IS_WINDOWS:
        return 'windows'
    elif IS_LINUX:
        return 'linux'
    elif IS_MAC:
        return 'mac'
    return 'unknown'


def normalize_path(path):
    """
    规范化路径，确保Windows兼容性
    
    Args:
        path: 原始路径（可以是Unix或Windows格式）
        
    Returns:
        str: 规范化后的路径
    """
    if path is None:
        return None
    
    # 将Unix风格路径转换为Windows风格
    if IS_WINDOWS:
        # 替换正斜杠为反斜杠
        path = path.replace('/', '\\')
        # 处理网络路径
        if path.startswith('\\\\'):
            return path
        # 处理普通路径
        return os.path.normpath(path)
    else:
        # Linux/Mac: 替换反斜杠为正斜杠
        return path.replace('\\', '/')


def join_path(*paths):
    """
    跨平台路径拼接
    
    Args:
        *paths: 路径组件
        
    Returns:
        str: 拼接后的路径
    """
    return os.path.join(*paths)


def get_project_root():
    """
    获取项目根目录
    
    Returns:
        str: 项目根目录的绝对路径
    """
    # 获取当前文件所在目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # 返回上级目录（项目根目录）
    return os.path.dirname(current_dir)


def get_data_dir():
    """
    获取数据目录
    
    Returns:
        str: 数据目录路径
    """
    return join_path(get_project_root(), 'data')


def get_logs_dir():
    """
    获取日志目录
    
    Returns:
        str: 日志目录路径
    """
    return join_path(get_project_root(), 'logs')


def get_config_dir():
    """
    获取配置目录
    
    Returns:
        str: 配置目录路径
    """
    return join_path(get_project_root(), 'config')


def ensure_dir_exists(directory):
    """
    确保目录存在，如果不存在则创建
    
    Args:
        directory: 目录路径
        
    Returns:
        bool: 是否成功
    """
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.debug('目录已创建: %s', directory)
        return True
    except Exception as e:
        logger.error('创建目录失败 %s: %s', directory, str(e))
        return False


def get_config_file_path(filename='config.yaml'):
    """
    获取配置文件路径
    
    Args:
        filename: 配置文件名
        
    Returns:
        str: 配置文件完整路径
    """
    # 优先使用Windows配置文件
    if IS_WINDOWS:
        windows_config = join_path(get_config_dir(), 'config_windows.yaml')
        if os.path.exists(windows_config):
            return windows_config
    
    return join_path(get_config_dir(), filename)


def setup_windows_environment():
    """
    设置Windows环境
    
    Returns:
        bool: 是否成功
    """
    if not IS_WINDOWS:
        return True
    
    try:
        # 添加项目根目录到Python路径
        project_root = get_project_root()
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        # 设置控制台编码
        import codecs
        if sys.stdout.encoding != 'utf-8':
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)
        if sys.stderr.encoding != 'utf-8':
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)
        
        # 确保必要目录存在
        ensure_dir_exists(get_data_dir())
        ensure_dir_exists(get_logs_dir())
        
        logger.info('Windows环境设置完成')
        return True
        
    except Exception as e:
        logger.error('Windows环境设置失败: %s', str(e))
        return False


def check_windows_prerequisites():
    """
    检查Windows先决条件
    
    Returns:
        dict: 检查结果
    """
    results = {
        'python_version': False,
        'pip_available': False,
        'npcap_installed': False,
        'virtual_env': False,
        'write_permissions': False
    }
    
    # 检查Python版本
    try:
        version = sys.version_info
        if version.major == 3 and version.minor >= 6:
            results['python_version'] = True
    except:
        pass
    
    # 检查pip
    try:
        import subprocess
        subprocess.check_call([sys.executable, '-m', 'pip', '--version'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        results['pip_available'] = True
    except:
        pass
    
    # 检查Npcap (用于Scapy)
    if IS_WINDOWS:
        try:
            import winreg
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r'SOFTWARE\WOW6432Node\Npcap')
                results['npcap_installed'] = True
            except FileNotFoundError:
                try:
                    winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                  r'SOFTWARE\Npcap')
                    results['npcap_installed'] = True
                except:
                    pass
        except:
            pass
    
    # 检查虚拟环境
    results['virtual_env'] = hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )
    
    # 检查写入权限
    try:
        test_file = join_path(get_project_root(), '.write_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        results['write_permissions'] = True
    except:
        pass
    
    return results


def print_prerequisites_report():
    """
    打印先决条件检查报告
    """
    results = check_windows_prerequisites()
    
    print("\n" + "="*60)
    print("Windows环境先决条件检查")
    print("="*60)
    
    status_map = {
        True: ('[PASS]', 'green'),
        False: ('[FAIL]', 'red')
    }
    
    items = [
        ('Python 3.6+', 'python_version'),
        ('pip可用', 'pip_available'),
        ('Npcap已安装', 'npcap_installed'),
        ('虚拟环境', 'virtual_env'),
        ('写入权限', 'write_permissions')
    ]
    
    for name, key in items:
        status, color = status_map[results[key]]
        print(f"{status} {name}")
    
    print("="*60 + "\n")
    
    # 提供建议
    if not results['python_version']:
        print("[建议] 请安装Python 3.6或更高版本")
        print("       下载地址: https://www.python.org/downloads/")
    
    if not results['pip_available']:
        print("[建议] pip未安装，请运行: python -m ensurepip")
    
    if not results['npcap_installed']:
        print("[建议] Npcap未安装，Scapy功能将受限")
        print("       下载地址: https://npcap.com/#download")
    
    if not results['virtual_env']:
        print("[建议] 建议使用虚拟环境运行项目")
        print("       创建命令: python -m venv venv")
    
    return all(results.values())


# 兼容性别名
get_project_dir = get_project_root
get_log_dir = get_logs_dir


if __name__ == '__main__':
    # 测试代码
    print("操作系统:", get_os_type())
    print("项目根目录:", get_project_root())
    print("数据目录:", get_data_dir())
    print("日志目录:", get_logs_dir())
    print("配置目录:", get_config_dir())
    print("配置文件:", get_config_file_path())
    
    print_prerequisites_report()
