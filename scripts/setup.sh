#!/bin/bash

################################################################################
#                                                                              #
#  SDN Network Security System - Setup Script (v2.0)                          #
#  改进版本 - 修复了输出问题，添加了调试功能                                      #
#  用法: bash scripts/setup.sh                                                 #
#                                                                              #
################################################################################

# 设置脚本选项
set -e  # 遇到错误立即退出

# ==================== 颜色和样式定义 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'  # No Color
BOLD='\033[1m'

# ==================== 日志和输出函数 ====================

# 时间戳函数
timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# 成功消息
success() {
    echo -e "${GREEN}[✓]${NC} $(timestamp) - $1"
}

# 错误消息
error() {
    echo -e "${RED}[✗]${NC} $(timestamp) - $1" >&2
}

# 警告消息
warning() {
    echo -e "${YELLOW}[! ]${NC} $(timestamp) - $1"
}

# 信息消息
info() {
    echo -e "${BLUE}[i]${NC} $(timestamp) - $1"
}

# 步骤标题
step() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}[STEP] $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
}

# 分隔线
separator() {
    echo -e "${MAGENTA}───────────────────────────────────────────────────────${NC}"
}

# 错误退出函数
error_exit() {
    error "$1"
    echo ""
    echo -e "${RED}安装失败！${NC}"
    exit 1
}

# ==================== 设置和清理 ====================

# 获取脚本目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( dirname "$SCRIPT_DIR" )"

# 改变到项目目录
cd "$PROJECT_DIR"

# 清理函数 - 如果安装失败则清理
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        error "脚本执行出错 (退出代码: $exit_code)"
        if [ -d "venv" ]; then
            warning "正在清理虚拟环境..."
            rm -rf venv
        fi
    fi
}

trap cleanup EXIT

# ==================== 打印欢迎信息 ====================

print_welcome() {
    echo ""
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║                                                        ║${NC}"
    echo -e "${BOLD}${CYAN}║     SDN Network Security System - Setup Script        ║${NC}"
    echo -e "${BOLD}${CYAN}║                    版本 2.0 (改进版)                  ║${NC}"
    echo -e "${BOLD}${CYAN}║                                                        ║${NC}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    info "项目目录: $PROJECT_DIR"
    info "脚本目录: $SCRIPT_DIR"
    echo ""
}

# ==================== 系统检查 ====================

check_os() {
    step "检查操作系统"

    if [[ ! "$OSTYPE" == "linux-gnu"* ]]; then
        error_exit "仅支持Linux系统，检测到:  $OSTYPE"
    fi

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        info "OS:  $PRETTY_NAME"
        success "操作系统检查通过"
    else
        warning "无法检测Linux发行版"
        success "操作系统检查通过"
    fi
}

check_python() {
    step "检查Python环境"

    if !  command -v python3 &> /dev/null; then
        error_exit "Python3 未安装。请运行: sudo apt-get install python3 python3-pip python3-venv"
    fi

    local python_version=$(python3 --version 2>&1 | awk '{print $2}')
    info "Python 版本: $python_version"

    # 检查版本是否 >= 3.6
    local major=$(echo $python_version | cut -d.  -f1)
    local minor=$(echo $python_version | cut -d. -f2)

    if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 6 ]); then
        error_exit "需要 Python 3.6 或更高版本，检测到: $python_version"
    fi

    success "Python 版本检查通过"
}

check_pip() {
    step "检查 pip"

    if ! command -v pip3 &> /dev/null; then
        error_exit "pip3 未安装。请运行: sudo apt-get install python3-pip"
    fi

    local pip_version=$(pip3 --version 2>&1 | awk '{print $2}')
    info "pip 版本:  $pip_version"

    success "pip 版本检查通过"
}

check_git() {
    step "检查 Git"

    if ! command -v git &> /dev/null; then
        warning "Git 未安装 (可选)"
    else
        local git_version=$(git --version | awk '{print $3}')
        info "Git 版本: $git_version"
        success "Git 已安装"
    fi
}

check_disk_space() {
    step "检查磁盘空间"

    local available=$(df "$PROJECT_DIR" | awk 'NR==2 {print $4}')
    info "可用空间: $available KB"

    if [ "$available" -lt 1000000 ]; then
        warning "磁盘空间可能不足 (建议至少 1GB)"
    else
        success "磁盘空间充足"
    fi
}

check_permissions() {
    step "检查文件权限"

    if [ ! -w "$PROJECT_DIR" ]; then
        error_exit "项目目录无写权限。请运行: sudo chown -R \$USER:\$USER $PROJECT_DIR"
    fi

    success "文件权限检查通过"
}

# ==================== 虚拟环境设置 ====================

setup_venv() {
    step "设置 Python 虚拟环境"

    # 检查并删除旧的虚拟环境
    if [ -d "venv" ]; then
        warning "检测到现存虚拟环境，正在删除..."
        rm -rf venv
        info "旧虚拟环境已删除"
    fi

    # 创建虚拟环境
    info "创建虚拟环境..."
    if !  python3 -m venv venv 2>&1 | head -5; then
        error_exit "虚拟环境创建失败"
    fi

    # 验证虚拟环境
    if [ !  -f "venv/bin/activate" ]; then
        error_exit "虚拟环境创建失败：激活脚本不存在"
    fi

    success "虚拟环境创建成功"
    info "虚拟环境位置: $PROJECT_DIR/venv"

    # 激活虚拟环境
    info "激活虚拟环境..."
    source venv/bin/activate

    if [ -z "$VIRTUAL_ENV" ]; then
        error_exit "虚拟环境激活失败"
    fi

    success "虚拟环��已激活:  $VIRTUAL_ENV"
}

# ==================== pip 升级 ====================

upgrade_pip() {
    step "升级 pip、setuptools 和 wheel"

    info "升级中...  (这可能需要一分钟)"

    if pip install --upgrade pip setuptools wheel 2>&1 | tail -1; then
        success "pip、setuptools 和 wheel 升级成功"
    else
        error_exit "pip 升级失败"
    fi
}

# ==================== 安装依赖 ====================

install_dependencies() {
    step "安装 Python 依赖"

    if [ !  -f "requirements.txt" ]; then
        error_exit "requirements.txt 未找到！"
    fi

    info "检测到 requirements.txt，开始安装依赖..."
    separator

    # 显示将要安装的包
    local package_count=$(grep -c "^[^#]" requirements.txt || echo 0)
    info "将安装 $package_count 个包"
    echo ""

    # 安装依赖，显示实时输出
    if pip install -r requirements.txt 2>&1; then
        separator
        success "所有依赖安装成功"
    else
        error_exit "依赖安装失败"
    fi
}

# ==================== 创建目录 ====================

create_directories() {
    step "创建必要的目录"

    local dirs=("logs" "data" "config" "docs" "tests" "scripts")

    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            info "创建目录: $dir"
        else
            info "目录已存在: $dir"
        fi
    done

    success "所有目录就绪"
}

# ==================== 数据库初始化 ====================

initialize_database() {
    step "初始化数据库"

    info "创建数据库...  (这可能需要一分钟)"

    python3 << 'EOF'
import sys
import os
sys.path.insert(0, '.')

try:
    from utils.db_helper import DatabaseHelper

    print("[INFO] 初始化数据库.. .", flush=True)
    db = DatabaseHelper()

    # 验证数据库
    info = db.get_database_info()
    db.disconnect()

    print(f"[INFO] 数据库初始化成功: {info. get('database_path')}", flush=True)

except ImportError as e:
    print(f"[WARNING] 无法导入数据库模块: {e}", flush=True)
    print("[INFO] 这在首次运行时是正常的", flush=True)
except Exception as e:
    print(f"[ERROR] 数据库初始化失败: {e}", flush=True)
    sys.exit(1)
EOF

    if [ $? -eq 0 ]; then
        success "数据库初始化成功"
    else
        warning "数据库初始化出现问题，但继续安装"
    fi
}

# ==================== 可选依赖检查 ====================

check_optional_dependencies() {
    step "检查可选依赖"

    # 检查 Ryu
    info "检查 Ryu..."
    if python3 -c "import ryu" 2>/dev/null; then
        local ryu_version=$(python3 -c "import ryu; print(ryu.__version__)" 2>/dev/null)
        success "Ryu 已安装 (版本: $ryu_version)"
    else
        warning "Ryu 未在虚拟环境中 (应该已随 requirements.txt 安装)"
    fi

    # 检查 scapy
    info "检查 scapy..."
    if python3 -c "import scapy" 2>/dev/null; then
        success "scapy 已安装"
    else
        warning "scapy 未安装"
    fi

    # 检查 sklearn
    info "检查 scikit-learn..."
    if python3 -c "import sklearn" 2>/dev/null; then
        success "scikit-learn 已安装"
    else
        warning "scikit-learn 未安装"
    fi

    # 检查 Mininet (系统级)
    info "检查 Mininet..."
    if command -v mn &> /dev/null; then
        success "Mininet 已安装 (系统级)"
    else
        warning "Mininet 未安装 (可选，用于网络仿真)"
        info "安装命令: sudo apt-get install mininet"
    fi

    # 检查 Open vSwitch
    info "检查 Open vSwitch..."
    if command -v ovs-vsctl &> /dev/null; then
        success "Open vSwitch 已安装"
    else
        warning "Open vSwitch 未安装"
        info "安装命令: sudo apt-get install openvswitch-switch"
    fi
}

# ==================== 配置文件检查 ====================

check_config_files() {
    step "检查配置文件"

    local config_files=("config/config.yaml" "config/rules.json")

    for file in "${config_files[@]}"; do
        if [ -f "$file" ]; then
            local size=$(du -h "$file" | awk '{print $1}')
            success "配置文件: $file ($size)"
        else
            warning "配置文件缺失: $file"
        fi
    done
}

# ==================== 权限设置 ====================

setup_permissions() {
    step "设置脚本权限"

    if [ -d "scripts" ]; then
        chmod +x scripts/*.sh 2>/dev/null || true
        chmod +x scripts/*. py 2>/dev/null || true
        success "脚���权限已配置"
    fi
}

# ==================== 测试模块导入 ====================

test_imports() {
    step "测试模块导入"

    python3 << 'EOF'
import sys
import os
sys. path.insert(0, '.')

modules = [
    ('utils.logger', 'setup_logger'),
    ('utils.db_helper', 'DatabaseHelper'),
    ('utils.network_utils', 'NetworkUtils'),
    ('modules.firewall', 'DynamicFirewall'),
    ('modules.traffic_monitor', 'TrafficCollector'),
    ('modules.intrusion_detection', 'DetectionEngine'),
    ('modules.anomaly_detection', 'KMeansAnalyzer'),
]

print("[INFO] 测试模块导入.. .", flush=True)
failed = []

for module_name, class_name in modules:
    try:
        parts = module_name.split('.')
        module = __import__(module_name, fromlist=[parts[-1]])
        obj = getattr(module, class_name)
        print(f"[INFO]   ✓ {module_name}. {class_name}", flush=True)
    except Exception as e:
        print(f"[WARNING] ✗ {module_name}:  {e}", flush=True)
        failed.append(module_name)

if failed:
    print(f"[WARNING] {len(failed)} 个模块导入失败，但这在首次运行时可能正常", flush=True)
else:
    print("[INFO] 所有模块导入成功", flush=True)
EOF

    success "模块导入测试完成"
}

# ==================== 生成信息文件 ====================

generate_info_files() {
    step "生成系统信息"

    info "生成 SYSTEM_INFO. txt..."

    cat > SYSTEM_INFO. txt << EOF
系统信息报告
========================
生成时间: $(date)

系统环境:
  主机名: $(hostname)
  OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")
  内核:  $(uname -r)
  架构: $(uname -m)

Python 信息:
  Python:  $(python3 --version 2>&1)
  Pip: $(pip3 --version)
  虚拟环境: $VIRTUAL_ENV

已安装包列表:
EOF

    pip list >> SYSTEM_INFO.txt 2>/dev/null || echo "pip list 失败" >> SYSTEM_INFO.txt

    success "系统信息已保存到 SYSTEM_INFO. txt"
}

# ==================== 生成快速开始指南 ====================

generate_quickstart() {
    step "生成快速开始指南"

    info "创建 QUICKSTART.md..."

    cat > QUICKSTART.md << 'EOF'
# 快速开始指南

## 安装完成！

### 下一步操作

#### 1. 激活虚拟环境

```bash
source venv/bin/activate
EOF

