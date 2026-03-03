# SDN网络安全系统 - 前端界面

基于 React + TypeScript + Tailwind CSS 构建的 SDN 网络安全系统前端界面。

## 功能特性

### 核心模块

1. **仪表盘 (Dashboard)**
   - 系统概览和实时状态
   - 流量趋势可视化
   - 告警统计和分布
   - 系统资源监控

2. **防火墙管理 (Firewall)**
   - 防火墙规则管理（增删改查）
   - 黑名单/白名单管理
   - 规则优先级设置
   - 实时规则切换

3. **流量监控 (Traffic Monitor)**
   - 实时流量采集和展示
   - 协议分布分析
   - 端口使用排行
   - 流量最多的主机统计
   - 历史流量趋势

4. **入侵检测 (Intrusion Detection)**
   - 实时告警监控
   - 告警严重程度分类
   - 攻击类型统计
   - 告警详情查看
   - 告警处理和标记

5. **异常检测 (Anomaly Detection)**
   - 基于K-means的异常识别
   - 聚类可视化
   - 异常分数展示
   - 异常类型分布
   - 异常处理和标记

6. **系统设置 (Settings)**
   - 通用系统配置
   - 各模块参数配置
   - 性能调优选项
   - 安全设置

## 技术栈

- **框架**: React 18.2+
- **语言**: TypeScript 5.2+
- **构建工具**: Vite 5.0+
- **样式**: Tailwind CSS 3.3+
- **路由**: React Router 6.20+
- **HTTP客户端**: Axios 1.6+
- **图表**: Recharts 2.10+
- **图标**: Lucide React 0.294+

## 项目结构

```
frontend/
├── src/
│   ├── components/       # 公共组件
│   │   └── Layout.tsx  # 布局组件
│   ├── lib/            # 工具库
│   │   ├── api.ts      # Axios配置
│   │   └── utils.ts    # 工具函数
│   ├── pages/          # 页面组件
│   │   ├── Dashboard.tsx
│   │   ├── Firewall.tsx
│   │   ├── TrafficMonitor.tsx
│   │   ├── IntrusionDetection.tsx
│   │   ├── AnomalyDetection.tsx
│   │   └── Settings.tsx
│   ├── services/       # API服务
│   │   └── api.ts     # API接口定义
│   ├── types/          # TypeScript类型定义
│   │   └── index.ts
│   ├── App.tsx         # 主应用组件
│   ├── main.tsx        # 应用入口
│   └── index.css      # 全局样式
├── public/             # 静态资源
├── index.html          # HTML模板
├── package.json        # 依赖配置
├── tsconfig.json       # TypeScript配置
├── vite.config.ts      # Vite配置
├── tailwind.config.js  # Tailwind配置
└── postcss.config.js   # PostCSS配置
```

## 安装和运行

### 安装依赖

```bash
cd frontend
npm install
```

### 开发模式

```bash
npm run dev
```

应用将在 `http://localhost:3000` 启动。

### 生产构建

```bash
npm run build
```

构建产物将输出到 `dist/` 目录。

### 预览生产构建

```bash
npm run preview
```

### 代码检查

```bash
npm run lint
```

## 环境变量

创建 `.env` 文件配置环境变量：

```env
VITE_API_URL=http://localhost:5000/api
```

## API集成

前端通过 REST API 与后端 SDN 控制器通信。API 基础路径通过 `VITE_API_URL` 环境变量配置。

### 主要API端点

- `GET /api/dashboard/stats` - 获取仪表盘统计数据
- `GET /api/firewall/rules` - 获取防火墙规则
- `POST /api/firewall/rules` - 添加防火墙规则
- `PUT /api/firewall/rules/:id` - 更新防火墙规则
- `DELETE /api/firewall/rules/:id` - 删除防火墙规则
- `GET /api/traffic/stats` - 获取流量统计
- `GET /api/detection/alerts` - 获取入侵检测告警
- `GET /api/anomaly/anomalies` - 获取异常检测结果

## 响应式设计

界面采用响应式设计，支持以下屏幕尺寸：

- **桌面**: ≥ 1024px
- **平板**: 768px - 1023px
- **移动**: < 768px

## UI/UX规范

### 颜色系统

- **主色调**: 蓝色 (#0ea5e9)
- **成功色**: 绿色 (#22c55e)
- **警告色**: 橙色 (#f59e0b)
- **危险色**: 红色 (#ef4444)
- **信息色**: 紫色 (#8b5cf6)

### 组件样式

- **卡片**: 白色背景，圆角，轻微阴影
- **按钮**: 圆角，悬停效果，状态反馈
- **输入框**: 圆角，聚焦高亮，错误提示
- **表格**: 分隔线，悬停高亮，响应式滚动

### 交互设计

- **加载状态**: 显示加载动画
- **错误处理**: 友好的错误提示
- **确认操作**: 危险操作需要确认
- **实时更新**: 关键数据自动刷新

## 性能优化

- **代码分割**: 使用 React.lazy 和 Suspense
- **图片优化**: 使用 WebP 格式，懒加载
- **缓存策略**: 合理使用 HTTP 缓存
- **防抖节流**: 频繁操作进行优化
- **虚拟滚动**: 大列表使用虚拟滚动

## 浏览器支持

- Chrome ≥ 90
- Firefox ≥ 88
- Safari ≥ 14
- Edge ≥ 90

## 开发指南

### 添加新页面

1. 在 `src/pages/` 创建新页面组件
2. 在 `src/App.tsx` 添加路由
3. 在 `src/components/Layout.tsx` 添加导航项

### 添加新API

1. 在 `src/types/index.ts` 定义类型
2. 在 `src/services/api.ts` 添加API函数
3. 在页面组件中使用API

### 自定义样式

1. 在 `src/index.css` 添加自定义样式
2. 使用 Tailwind 的 `@layer` 指令组织样式
3. 遵循 BEM 命名规范

## 故障排除

### API连接失败

- 检查后端服务是否运行
- 确认 `VITE_API_URL` 配置正确
- 查看浏览器控制台错误信息

### 构建失败

- 清除 `node_modules` 重新安装
- 检查 TypeScript 类型错误
- 确认所有依赖已正确安装

### 样式问题

- 确认 Tailwind CSS 已正确配置
- 检查 `index.css` 是否被正确导入
- 清除浏览器缓存

## 许可证

MIT License

## 联系方式

如有问题或建议，请联系开发团队。
