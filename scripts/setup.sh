#!/bin/bash

################################################################################
#                                                                              #
#  SDN Network Security System - Setup Script (v3.0 - Python 3.6 Compatible)  #
#  适配 Python 3.6 和 Ryu 4.26                                                #
#                                                                              #
################################################################################

set -e

# ==================== 颜色定义 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ==================== 函数定义 ====================

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[! ]${NC} $1"
}

info() {
    echo -e "${BLUE}[i]${NC} $1"
}

step() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ==================== 主函数 ====================

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  SDN Network Security System Setup (v3.0)             ║${NC}"
    echo -e "${CYAN}║  Python 3.6 & Ryu 4.26 Compatible                    ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""

    PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    cd "$PROJECT_DIR"

    info "项目目录: $PROJECT_DIR"
    echo ""

    # ========== Step 1: 系统检查 ==========
    step "Step 1: 检查系统要求"

    # 检查Python版本
    if ! command -v python3.6 &> /dev/null; then
        warning "Python 3.6 未找到，尝试使用 python3"
        if !  command -v python3 &> /dev/null; then
            error "Python 3 未安装"
            exit 1
        fi
        PYTHON_CMD="python3"
    else
        PYTHON_CMD="python3.6"
    fi

    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    info "Python 版本: $PYTHON_VERSION"
    success "Python 检查通过"
    echo ""

    # ========== Step 2: 虚拟环境 ==========
    step "Step 2: 设置虚拟环境"

    if [ -d "venv" ]; then
        warning "检测到旧虚拟环境，正在删除..."
        rm -rf venv
    fi

    info "创建虚拟环境..."
    if $PYTHON_CMD -m venv venv; then
        success "虚拟环境创建成功"
    else
        error "虚拟环境创建失败"
        exit 1
    fi

    info "激活虚拟环境..."
    source venv/bin/activate
    success "虚拟环境已激活"
    echo ""

    # ========== Step 3: 升级 pip ==========
    step "Step 3: 升级 pip"

    info "升级中...  (这可能需要几分钟)"
    python -m pip install --upgrade pip setuptools wheel > /dev/null 2>&1
    success "pip 升级成功"
    echo ""

    # ========== Step 4: 安装依赖 ==========
    step "Step 4: 安装 Python 依赖"

    if [ !  -f "requirements.txt" ]; then
        error "requirements.txt 未找到"
        exit 1
    fi

    info "正在安装依赖包..."
    if pip install -r requirements.txt; then
        success "依赖包安装成功"
    else
        error "依赖包安装失败"
        exit 1
    fi
    echo ""

    # ========== Step 5: 创建目录 ==========
    step "Step 5: 创建必要目录"

    for dir in logs data config docs tests scripts; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            info "目录已创建: $dir"
        fi
    done
    success "目录创建完成"
    echo ""

    # ========== Step 6: 验证安装 ==========
    step "Step 6: 验证 Ryu 4.26 安装"

    if python -c "import ryu; print(ryu.__version__)" 2>/dev/null | grep -q "4.26"; then
        success "Ryu 4.26 已正确安装"
    else
        warning "Ryu 版本不是 4.26，但继续安装..."
    fi
    echo ""

    # ========== Step 7: 测试导入 ==========
    step "Step 7: 测试模块导入"

    python << 'EOF'
import sys
print("[INFO] 测试 Python 版本...")
if sys.version_info < (3, 6):
    print("[ERROR] Python 版本低于 3.6")
    sys.exit(1)

print("[INFO] Python 版本:  {0}. {1}".format(sys. version_info.major, sys. version_info.minor))
print("[INFO] 测试 Ryu 导入...")
try:
    import ryu
    print("[SUCCESS] Ryu 导入成功")
except ImportError as e:
    print("[ERROR] Ryu 导入失败:  {0}".format(str(e)))
    sys.exit(1)

print("[INFO] 测试其他模块...")
try:
    import scapy
    print("[SUCCESS] scapy 导入成功")
except ImportError:
    print("[WARNING] scapy 未安装")

try:
    import sklearn
    print("[SUCCESS] scikit-learn 导入成功")
except ImportError:
    print("[WARNING] scikit-learn 未安装")

print("[SUCCESS] 所有关键模块导入成功")
EOF

    success "模块导入验证完成"
    echo ""

    # ========== 完成 ==========
    step "安装完成"

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ 安装成功！系统已为 Python 3.6 配置完毕            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${BLUE}后续步骤:${NC}"
    echo -e "  1. 激活虚拟环境:"
    echo -e "     ${YELLOW}source venv/bin/activate${NC}"
    echo ""
    echo -e "  2. 启动 Ryu 控制器:"
    echo -e "     ${YELLOW}ryu-manager controllers/ryu_controller.py${NC}"
    echo ""
    echo -e "  3. 启动 Mininet (在另一个终端):"
    echo -e "     ${YELLOW}sudo python scripts/mininet_topo.py${NC}"
    echo ""
}

# ==================== 执行主函数 ====================

main "$@"