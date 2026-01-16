# API 文档

## 控制器API

### 1. 防火墙API

#### 添加规则
POST /api/firewall/rules { "id": 1, "name": "Allow HTTP", "action": "ALLOW", "protocol": "TCP", "dst_port": 80, "priority": 50 }



#### 删除规则
DELETE /api/firewall/rules/{id}



#### 获取所有规则
GET /api/firewall/rules



### 2. 流量监控API

#### 获取流统计
GET /api/traffic/statistics



#### 获取流量报告
GET /api/traffic/report? hours=24



### 3. 入侵检测API

#### 获取告警列表
GET /api/alerts/intrusions? limit=100&hours=24



#### 获取异常告警
GET /api/alerts/anomalies?limit=100
