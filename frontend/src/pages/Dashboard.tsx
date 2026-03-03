import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, Brain, Server, Cpu, HardDrive, Clock } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell } from 'recharts';
import { formatBytes, formatNumber, formatDate } from '../lib/utils';
import { dashboardApi } from '../services/api';

interface DashboardData {
  firewall: {
    total_rules: number;
    blacklist_size: number;
    whitelist_size: number;
  };
  traffic: {
    total_flows: number;
    bandwidth_usage: number;
  };
  detection: {
    total_alerts: number;
    alerts_by_severity: Record<string, number>;
  };
  anomaly: {
    total_anomalies: number;
  };
  system: {
    controller_status: string;
    switch_count: number;
    cpu_usage: number;
    memory_usage: number;
    uptime: number;
  };
  recent_alerts: any[];
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      const response = await dashboardApi.getStats();
      setData(response);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const COLORS = ['#0ea5e9', '#22c55e', '#f59e0b', '#ef4444'];

  const severityData = data?.detection?.alerts_by_severity
    ? Object.entries(data.detection.alerts_by_severity).map(([name, value]) => ({
        name,
        value: value as number,
      }))
    : [];

  const trafficData = [
    { name: '00:00', flows: 1200, bandwidth: 45 },
    { name: '04:00', flows: 800, bandwidth: 30 },
    { name: '08:00', flows: 2500, bandwidth: 95 },
    { name: '12:00', flows: 3200, bandwidth: 120 },
    { name: '16:00', flows: 2800, bandwidth: 105 },
    { name: '20:00', flows: 2000, bandwidth: 75 },
    { name: '24:00', flows: 1500, bandwidth: 55 },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">仪表盘</h1>
          <p className="text-gray-600 mt-1">系统概览和实时状态</p>
        </div>
        <div className="text-sm text-gray-500">
          最后更新: {formatDate(new Date().toISOString())}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={Shield}
          title="防火墙规则"
          value={data?.firewall?.total_rules || 0}
          subtitle={`${data?.firewall?.blacklist_size || 0} 黑名单`}
          color="blue"
        />
        <StatCard
          icon={Activity}
          title="活跃流"
          value={formatNumber(data?.traffic?.total_flows || 0)}
          subtitle={formatBytes(data?.traffic?.bandwidth_usage || 0) + '/s'}
          color="green"
        />
        <StatCard
          icon={AlertTriangle}
          title="安全告警"
          value={data?.detection?.total_alerts || 0}
          subtitle="今日新增"
          color="orange"
        />
        <StatCard
          icon={Brain}
          title="异常检测"
          value={data?.anomaly?.total_anomalies || 0}
          subtitle="待处理"
          color="purple"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">流量趋势</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="flows" stroke="#0ea5e9" strokeWidth={2} />
              <Line type="monotone" dataKey="bandwidth" stroke="#22c55e" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">告警严重程度分布</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card lg:col-span-2">
          <h3 className="text-lg font-semibold mb-4">最近告警</h3>
          <div className="space-y-3">
            {data?.recent_alerts?.slice(0, 5).map((alert: any) => (
              <AlertItem key={alert.id} alert={alert} />
            ))}
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">系统状态</h3>
          <div className="space-y-4">
            <SystemStatusItem
              icon={Server}
              label="控制器状态"
              value={data?.system?.controller_status === 'online' ? '在线' : '离线'}
              status={data?.system?.controller_status === 'online' ? 'success' : 'error'}
            />
            <SystemStatusItem
              icon={Server}
              label="交换机数量"
              value={data?.system?.switch_count || 0}
            />
            <SystemStatusItem
              icon={Cpu}
              label="CPU 使用率"
              value={`${data?.system?.cpu_usage || 0}%`}
              progress={data?.system?.cpu_usage || 0}
            />
            <SystemStatusItem
              icon={HardDrive}
              label="内存使用率"
              value={`${data?.system?.memory_usage || 0}%`}
              progress={data?.system?.memory_usage || 0}
            />
            <SystemStatusItem
              icon={Clock}
              label="运行时间"
              value={`${Math.floor((data?.system?.uptime || 0) / 3600)} 小时`}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

interface StatCardProps {
  icon: React.ElementType;
  title: string;
  value: string | number;
  subtitle: string;
  color: 'blue' | 'green' | 'orange' | 'purple';
}

function StatCard({ icon: Icon, title, value, subtitle, color }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    green: 'bg-green-100 text-green-600',
    orange: 'bg-orange-100 text-orange-600',
    purple: 'bg-purple-100 text-purple-600',
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
          <p className="text-sm text-gray-500 mt-1">{subtitle}</p>
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}

interface AlertItemProps {
  alert: any;
}

function AlertItem({ alert }: AlertItemProps) {
  const severityColors = {
    LOW: 'bg-blue-100 text-blue-800',
    MEDIUM: 'bg-yellow-100 text-yellow-800',
    HIGH: 'bg-orange-100 text-orange-800',
    CRITICAL: 'bg-red-100 text-red-800',
  };

  return (
    <div className="flex items-start justify-between p-3 bg-gray-50 rounded-lg">
      <div className="flex-1">
        <div className="flex items-center space-x-2">
          <span className={`badge ${severityColors[alert.severity]}`}>
            {alert.severity}
          </span>
          <span className="text-sm text-gray-600">{alert.type}</span>
        </div>
        <p className="text-sm text-gray-900 mt-1">{alert.message}</p>
        <p className="text-xs text-gray-500 mt-1">{formatDate(alert.timestamp)}</p>
      </div>
    </div>
  );
}

interface SystemStatusItemProps {
  icon: React.ElementType;
  label: string;
  value: string | number;
  status?: 'success' | 'error';
  progress?: number;
}

function SystemStatusItem({ icon: Icon, label, value, status, progress }: SystemStatusItemProps) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center space-x-3">
        <Icon className="w-5 h-5 text-gray-400" />
        <span className="text-sm text-gray-600">{label}</span>
      </div>
      <div className="flex items-center space-x-2">
        {status && (
          <div className={`w-2 h-2 rounded-full ${status === 'success' ? 'bg-green-500' : 'bg-red-500'}`} />
        )}
        {progress !== undefined ? (
          <div className="flex items-center space-x-2">
            <div className="w-24 h-2 bg-gray-200 rounded-full overflow-hidden">
              <div
                className="h-full bg-primary-600 transition-all"
                style={{ width: `${progress}%` }}
              />
            </div>
            <span className="text-sm font-medium text-gray-900">{value}</span>
          </div>
        ) : (
          <span className="text-sm font-medium text-gray-900">{value}</span>
        )}
      </div>
    </div>
  );
}
