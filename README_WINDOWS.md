# SDN网络安全系统 - Windows版本

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue)](https://www.microsoft.com/windows)
[![Python](https://img.shields.io/badge/Python-3.6+-green)](https://www.python.org/)
[![Ryu](https://img.shields.io/badge/Ryu-4.34-orange)](https://ryu-sdn.org/)

> **注意**: 这是SDN网络安全系统的Windows兼容版本。原项目为Linux设计，此版本专门针对Windows 10/11进行了适配。

## 快速开始

### 1. 环境准备

确保已安装以下软件：
- [Python 3.6+](https://www.python.org/downloads/) (勾选"Add Python to PATH")
- [Npcap](https://npcap.com/#download) (用于网络数据包捕获)
- [Node.js 16+](https://nodejs.org/) (用于前端，可选)

### 2. 一键安装

```cmd
git clone <repository-url>
cd sdn-network-security
scripts\setup.bat
```

### 3. 启动服务

启动SDN控制器：
```cmd
run.bat controller
```

启动前端界面（可选）：
```cmd
run.bat frontend
```

访问 http://localhost:3000 查看Web界面

## 项目特点

### 🚀 Windows原生支持
- 完整的Windows批处理脚本
- 自动路径格式转换
- UTF-8编码支持
- Windows服务支持（可选）

### 🔧 简化安装流程
- 一键安装脚本 (`setup.bat`)
- 自动创建虚拟环境
- 自动安装依赖
- 环境检测和验证

### 📊 完整功能模块
- ✅ 动态防火墙管理
- ✅ 实时流量监控
- ✅ 入侵检测系统 (IDS)
- ✅ 异常检测 (K-means机器学习)
- ✅ 可视化Web界面
- ✅ RESTful API

### 🛡️ 安全特性
- 黑白名单管理
- 规则优先级控制
- 实时威胁检测
- 流量异常分析
- 完整日志记录

## 文件说明

### Windows特定文件

| 文件 | 说明 |
|------|------|
| `scripts\setup.bat` | Windows安装脚本 |
| `run.bat` | Windows运行脚本 |
| `test.bat` | Windows测试脚本 |
| `scripts\frontend.bat` | 前端启动脚本 |
| `config\config_windows.yaml` | Windows配置文件 |
| `requirements_windows.txt` | Windows依赖配置 |
| `utils\windows_compat.py` | Windows兼容性模块 |
| `WINDOWS_SETUP_GUIDE.md` | 详细安装指南 |
| `README_WINDOWS.md` | 本文件 |

### 核心模块

```
sdn-network-security/
├── controllers/          # SDN控制器
│   └── ryu_controller.py # 主控制器
├── modules/              # 功能模块
│   ├── firewall/         # 防火墙模块
│   ├── traffic_monitor/  # 流量监控
│   ├── intrusion_detection/ # 入侵检测
│   └── anomaly_detection/   # 异常检测
├── frontend/             # Web界面
│   └── src/              # React前端源码
└── utils/                # 工具模块
    └── windows_compat.py # Windows兼容层
```

## 使用指南

### 命令行操作

```cmd
# 显示帮助
run.bat help

# 启动SDN控制器
run.bat controller

# 启动前端界面
run.bat frontend

# 启动API服务器
run.bat api

# 运行测试
run.bat test
```

### Web界面

启动后访问 http://localhost:3000

功能模块：
- **仪表盘**: 系统概览和实时状态
- **防火墙**: 规则管理、黑白名单
- **流量监控**: 实时流量分析和统计
- **入侵检测**: 安全告警和威胁分析
- **异常检测**: 机器学习异常识别
- **系统设置**: 参数配置

### API接口

控制器启动后，API文档可通过以下地址访问：
- Swagger UI: http://localhost:5000/docs
- ReDoc: http://localhost:5000/redoc

## 配置说明

### 主配置文件

`config\config_windows.yaml`

重要配置项：
```yaml
# 日志路径（Windows格式）
logging:
  handlers:
    file:
      filename: "logs\\sdn_security.log"

# 数据库路径
database:
  path: "data\\sdn_security.db"

# OpenFlow端口
ryu_controller:
  port: 6633

# API端口
api:
  port: 5000
```

### 防火墙规则

`config\rules.json`

```json
{
  "rules": [
    {
      "id": 1,
      "name": "允许HTTP",
      "action": "ALLOW",
      "protocol": "TCP",
      "dst_port": 80,
      "priority": 100
    }
  ],
  "blacklist": ["192.168.1.100"],
  "whitelist": ["192.168.1.1"]
}
```

## 开发指南

### 目录结构

```
sdn-network-security/
├── config/               # 配置文件
├── controllers/          # SDN控制器
├── modules/              # 功能模块
├── scripts/              # 脚本文件
├── tests/                # 测试代码
├── utils/                # 工具模块
├── frontend/             # 前端代码
├── logs/                 # 日志目录（自动创建）
├── data/                 # 数据目录（自动创建）
└── venv/                 # 虚拟环境（自动创建）
```

### 添加新模块

1. 在 `modules/` 创建新目录
2. 添加 `__init__.py` 和模块代码
3. 在 `controllers/ryu_controller.py` 中导入
4. 添加相应的测试文件

### 前端开发

```cmd
cd frontend
npm install
npm run dev      # 开发模式
npm run build    # 生产构建
npm run lint     # 代码检查
```

## 故障排除

### 常见问题

#### 1. Python命令找不到
```cmd
# 检查Python安装
python --version

# 如果失败，尝试
py --version
```

#### 2. 虚拟环境创建失败
```cmd
# 手动创建
python -m venv venv

# 激活
venv\Scripts\activate

# 安装依赖
pip install -r requirements_windows.txt
```

#### 3. Scapy/Npcap警告
```
WARNING: No libpcap provider available
```
**解决**: 安装Npcap并勾选 "WinPcap API-compatible Mode"

#### 4. 端口被占用
```cmd
# 查找占用6633端口的进程
netstat -ano | findstr :6633

# 结束进程
taskkill /PID <进程ID> /F
```

### 日志查看

```cmd
# 实时查看日志
type logs\sdn_security.log

# 查看错误日志
type logs\errors.log
```

### 调试模式

```cmd
set LOG_LEVEL=DEBUG
run.bat controller
```

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                     Web界面 (React)                          │
│                  http://localhost:3000                      │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP/REST API
┌──────────────────────▼──────────────────────────────────────┐
│                    API服务器 (Flask)                         │
│                  http://localhost:5000                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                 SDN控制器 (Ryu)                              │
│  ┌──────────────┬──────────────┬──────────────┬───────────┐ │
│  │   防火墙     │  流量监控    │  入侵检测    │ 异常检测  │ │
│  │  Firewall    │   Traffic    │     IDS      │  Anomaly  │ │
│  └──────────────┴──────────────┴──────────────┴───────────┘ │
└──────────────────────┬──────────────────────────────────────┘
                       │ OpenFlow 1.3
┌──────────────────────▼──────────────────────────────────────┐
│              OpenFlow交换机 (物理/虚拟)                       │
└─────────────────────────────────────────────────────────────┘
```

## 技术栈

### 后端
- **Python 3.6+**: 主要开发语言
- **Ryu 4.34**: SDN控制器框架
- **Flask 1.1+**: Web API框架
- **Scapy 2.4+**: 网络数据包处理
- **Scikit-learn**: 机器学习库
- **SQLAlchemy**: 数据库ORM

### 前端
- **React 18**: UI框架
- **TypeScript**: 类型安全
- **Tailwind CSS**: 样式框架
- **Recharts**: 数据可视化
- **Vite**: 构建工具

### 工具
- **pytest**: 测试框架
- **flake8**: 代码检查
- **black**: 代码格式化

## 性能指标

- **控制平面延迟**: < 10ms
- **流表下发速度**: > 1000 flows/sec
- **数据包处理**: > 10,000 packets/sec
- **API响应时间**: < 50ms
- **前端加载时间**: < 2s

## 限制说明

### Windows特定限制

1. **Mininet不支持**: Mininet网络仿真工具不支持Windows
   - 替代方案: 使用WSL、虚拟机或真实OpenFlow交换机

2. **Snort集成**: Windows上Snort配置较复杂
   - 默认禁用，可手动启用

3. **性能**: Windows下性能可能略低于Linux
   - 建议生产环境使用Linux

### 推荐配置

- **开发环境**: Windows 10/11 + Python 3.8/3.9
- **生产环境**: Ubuntu 20.04 LTS + Python 3.8

## 贡献指南

1. Fork项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建Pull Request

## 许可证

MIT License

## 联系方式

- 项目主页: [GitHub Repository]
- 问题反馈: [Issues]
- 邮件: your-email@example.com

## 致谢

- [Ryu SDN Framework](https://ryu-sdn.org/)
- [OpenFlow](https://opennetworking.org/)
- [React](https://reactjs.org/)
- [Tailwind CSS](https://tailwindcss.com/)

---

**注意**: 本项目仅供学习和研究使用。在生产环境部署前，请进行充分测试。

**最后更新**: 2024年
