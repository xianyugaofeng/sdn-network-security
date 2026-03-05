# SDN网络安全系统 - Windows安装配置指南

## 概述

本指南详细介绍如何在Windows 10及以上版本系统中安装、配置和运行SDN网络安全系统。

## 系统要求

### 硬件要求
- **CPU**: 双核处理器或更高
- **内存**: 4GB RAM（推荐8GB）
- **硬盘**: 至少2GB可用空间
- **网络**: 以太网或WiFi连接

### 软件要求
- **操作系统**: Windows 10 (64位) 或 Windows 11
- **Python**: 3.6 或更高版本
- **Node.js**: 16.x 或更高版本（用于前端）
- **Npcap**: 0.9990 或更高版本（用于网络数据包捕获）

## 安装步骤

### 第一步：安装Python

1. 访问 [Python官网](https://www.python.org/downloads/)
2. 下载 Python 3.6+ 版本（推荐 3.8 或 3.9）
3. **重要**: 安装时勾选 **"Add Python to PATH"**
4. 选择 **"Customize installation"**
5. 确保勾选 **"pip"** 和 **"Add Python to environment variables"**
6. 完成安装

验证安装：
```cmd
python --version
pip --version
```

### 第二步：安装Npcap

Npcap是Scapy在Windows上运行所需的网络驱动。

1. 访问 [Npcap官网](https://npcap.com/#download)
2. 下载 Npcap 安装程序
3. **重要**: 安装时勾选以下选项：
   - ✅ "Install Npcap in WinPcap API-compatible Mode"
   - ✅ "Support raw 802.11 traffic (and monitor mode)"
4. 完成安装

### 第三步：安装Visual C++ Build Tools（可选）

某些Python包需要编译工具：

1. 访问 [Visual Studio下载页面](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
2. 下载并安装 "Build Tools for Visual Studio"
3. 安装时选择 **"C++ build tools"** 工作负载
4. 勾选 **"Windows 10 SDK"**

### 第四步：克隆/解压项目

将项目文件解压到目标目录，例如：
```
C:\Users\YourName\Projects\sdn-network-security
```

### 第五步：运行安装脚本

1. 打开命令提示符（CMD）或 PowerShell
2. 切换到项目目录：
```cmd
cd C:\Users\YourName\Projects\sdn-network-security
```

3. 运行安装脚本：
```cmd
scripts\setup.bat
```

安装脚本将自动完成以下操作：
- ✅ 检查Python环境
- ✅ 创建虚拟环境 (`venv`)
- ✅ 安装所有依赖包
- ✅ 创建必要的目录结构
- ✅ 验证关键模块
- ✅ 创建Windows运行脚本

### 第六步：安装前端依赖（可选）

如果需要运行前端界面：

1. 安装Node.js：
   - 访问 [Node.js官网](https://nodejs.org/)
   - 下载 LTS 版本（推荐 18.x 或 20.x）
   - 运行安装程序

2. 验证安装：
```cmd
node --version
npm --version
```

## 项目结构

安装完成后，项目目录结构如下：

```
sdn-network-security/
├── config/                     # 配置文件
│   ├── config.yaml            # 主配置文件
│   └── config_windows.yaml    # Windows配置文件
├── controllers/               # SDN控制器
│   ├── ryu_controller.py
│   └── flow_manager.py
├── modules/                   # 功能模块
│   ├── firewall/
│   ├── traffic_monitor/
│   ├── intrusion_detection/
│   └── anomaly_detection/
├── scripts/                   # 脚本文件
│   ├── setup.bat             # Windows安装脚本
│   ├── setup.sh              # Linux安装脚本
│   ├── mininet_topo.py       # 网络拓扑
│   └── frontend.bat          # 前端启动脚本
├── tests/                     # 测试文件
├── utils/                     # 工具模块
│   ├── windows_compat.py     # Windows兼容性模块
│   ├── logger.py
│   └── db_helper.py
├── frontend/                  # 前端界面
│   ├── src/
│   ├── package.json
│   └── ...
├── venv/                      # Python虚拟环境
├── logs/                      # 日志目录
├── data/                      # 数据目录
├── run.bat                    # Windows运行脚本
├── test.bat                   # Windows测试脚本
├── requirements.txt           # Python依赖
├── requirements_windows.txt   # Windows特定依赖
└── WINDOWS_SETUP_GUIDE.md    # 本指南
```

## 运行项目

### 启动SDN控制器

```cmd
run.bat controller
```

或手动运行：
```cmd
venv\Scripts\activate
ryu-manager --verbose controllers\ryu_controller.py
```

### 启动前端界面

```cmd
run.bat frontend
```

或手动运行：
```cmd
cd frontend
npm install
npm run dev
```

前端将在 http://localhost:3000 启动

### 启动API服务器

```cmd
run.bat api
```

### 查看帮助

```cmd
run.bat help
```

## 运行测试

### 运行所有测试

```cmd
test.bat
```

### 运行特定模块测试

```cmd
test.bat firewall    # 防火墙模块
test.bat ids         # 入侵检测模块
test.bat traffic     # 流量监控模块
test.bat anomaly     # 异常检测模块
```

## 配置说明

### 配置文件位置

- **主配置**: `config\config_windows.yaml`
- **防火墙规则**: `config\rules.json`

### 重要配置项

#### 日志路径（Windows格式）
```yaml
logging:
  handlers:
    file:
      filename: "logs\\sdn_security.log"
    error_file:
      filename: "logs\\errors.log"
```

#### 数据库路径（Windows格式）
```yaml
database:
  path: "data\\sdn_security.db"
```

#### Snort路径（如果使用）
```yaml
intrusion_detection:
  snort_path: "C:\\Program Files\\Snort\\bin\\snort.exe"
  snort_conf: "C:\\Program Files\\Snort\\etc\\snort.conf"
```

## 常见问题

### 1. Python命令找不到

**问题**: `'python' 不是内部或外部命令`

**解决**:
1. 重新安装Python，勾选 "Add Python to PATH"
2. 或手动添加Python到系统环境变量

### 2. pip安装失败

**问题**: 依赖包安装失败

**解决**:
```cmd
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements_windows.txt
```

### 3. Scapy/Npcap问题

**问题**: `WARNING: No libpcap provider available`

**解决**:
1. 确保Npcap已正确安装
2. 检查Npcap是否勾选 "WinPcap API-compatible Mode"
3. 重启计算机

### 4. Ryu启动失败

**问题**: `ImportError: No module named 'ryu'`

**解决**:
```cmd
venv\Scripts\activate
pip install ryu==4.34
```

### 5. 前端npm install失败

**问题**: 前端依赖安装失败

**解决**:
```cmd
cd frontend
npm cache clean --force
npm install --registry=https://registry.npmmirror.com
```

### 6. 权限问题

**问题**: 无法创建目录或写入文件

**解决**:
1. 以管理员身份运行CMD或PowerShell
2. 检查目录权限
3. 将项目移动到用户目录下

## 注意事项

### 1. Mininet不支持Windows

Mininet网络仿真工具不支持Windows。如需使用Mininet：
- 使用WSL (Windows Subsystem for Linux)
- 使用虚拟机（VirtualBox/VMware）运行Linux
- 使用Docker容器

### 2. 防火墙设置

Windows Defender防火墙可能阻止OpenFlow通信：
1. 打开 "Windows Defender 防火墙"
2. 点击 "允许应用通过防火墙"
3. 添加Python和Ryu相关程序
4. 开放端口 6633 (OpenFlow) 和 5000 (API)

### 3. 路径格式

Windows使用反斜杠 (`\`) 作为路径分隔符。配置文件已自动处理，但手动编辑时注意：
- ✅ 正确: `logs\\app.log`
- ❌ 错误: `logs/app.log`

### 4. 编码问题

Windows默认使用GBK编码，项目已配置UTF-8：
- 所有Python文件包含 `# -*- coding: utf-8 -*-`
- 批处理脚本使用 `chcp 65001` 设置UTF-8

## 性能优化

### 1. 禁用Windows Defender实时保护（开发环境）

添加项目目录到排除项：
1. Windows安全中心 → 病毒和威胁防护
2. 管理设置 → 排除项
3. 添加项目文件夹

### 2. 使用SSD

将项目放在SSD上可显著提升性能，特别是：
- 数据库操作
- 日志写入
- 前端构建

### 3. 调整Python内存限制

创建 `python.ini` 在项目根目录：
```ini
[global]
optimize = 1
```

## 卸载

1. 删除虚拟环境：
```cmd
rmdir /s /q venv
```

2. 删除Node模块（如果使用前端）：
```cmd
cd frontend
rmdir /s /q node_modules
```

3. 删除日志和数据：
```cmd
rmdir /s /q logs
rmdir /s /q data
```

## 技术支持

### 日志文件

遇到问题请查看日志：
- `logs\sdn_security.log` - 应用日志
- `logs\errors.log` - 错误日志
- `logs\sdn_controller.log` - 控制器日志

### 调试模式

启用调试模式获取更多日志：
```cmd
set LOG_LEVEL=DEBUG
run.bat controller
```

### 获取帮助

- 查看项目文档: `docs\`
- 查看API文档: `docs\api_documentation.md`
- 提交Issue: 项目GitHub页面

## 更新日志

### v1.0.0 (Windows版本)
- ✅ 完整的Windows安装脚本
- ✅ Windows批处理运行脚本
- ✅ Windows特定依赖配置
- ✅ Windows兼容性模块
- ✅ 路径自动转换
- ✅ UTF-8编码支持
- ✅ 详细安装指南

## 许可证

MIT License

---

**注意**: 本指南适用于Windows 10/11系统。Linux/Mac用户请参考原项目文档。
