import React, { useState, useEffect } from 'react';
import { AlertTriangle, Shield, RefreshCw, CheckCircle, XCircle, Search, Filter, AlertCircle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell } from 'recharts';
import { Alert, DetectionStats } from '../types';
import { detectionApi } from '../services/api';
import { formatDate, getSeverityColor } from '../lib/utils';

export default function IntrusionDetection() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<DetectionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [filterSeverity, filterType]);

  const loadData = async () => {
    try {
      const [alertsData, statsData] = await Promise.all([
        detectionApi.getAlerts(100),
        detectionApi.getStats(),
      ]);
      setAlerts(alertsData);
      setStats(statsData);
    } catch (error) {
      console.error('Failed to load detection data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleResolveAlert = async (id: string) => {
    try {
      await detectionApi.resolveAlert(id);
      setAlerts(alerts.map(alert => 
        alert.id === id ? { ...alert, resolved: true } : alert
      ));
    } catch (error) {
      console.error('Failed to resolve alert:', error);
    }
  };

  const severityData = stats?.alerts_by_severity
    ? Object.entries(stats.alerts_by_severity).map(([name, value]) => ({
        name,
        value: value as number,
      }))
    : [];

  const typeData = stats?.alerts_by_type
    ? Object.entries(stats.alerts_by_type)
        .sort(([, a], [, b]) => (b as number) - (a as number))
        .slice(0, 10)
        .map(([name, value]) => ({
          name: name.length > 20 ? name.substring(0, 20) + '...' : name,
          fullName: name,
          value: value as number,
        }))
    : [];

  const alertTrendData = [
    { time: '00:00', alerts: 12, resolved: 10 },
    { time: '04:00', alerts: 8, resolved: 7 },
    { time: '08:00', alerts: 25, resolved: 20 },
    { time: '12:00', alerts: 32, resolved: 28 },
    { time: '16:00', alerts: 28, resolved: 25 },
    { time: '20:00', alerts: 18, resolved: 15 },
    { time: '24:00', alerts: 15, resolved: 12 },
  ];

  const COLORS = ['#22c55e', '#f59e0b', '#f97316', '#ef4444'];

  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = filterSeverity === 'ALL' || alert.severity === filterSeverity;
    const matchesType = filterType === 'ALL' || alert.type.includes(filterType);
    const matchesSearch = !searchTerm || 
      alert.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.source_ip?.includes(searchTerm) ||
      alert.dest_ip?.includes(searchTerm);
    return matchesSeverity && matchesType && matchesSearch;
  });

  const unresolvedAlerts = filteredAlerts.filter(alert => !alert.resolved);

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
          <h1 className="text-2xl font-bold text-gray-900">入侵检测</h1>
          <p className="text-gray-600 mt-1">实时监控和响应安全威胁</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={loadData}
            className="btn btn-outline flex items-center space-x-2"
          >
            <RefreshCw className="w-4 h-4" />
            <span>刷新</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard
          title="总告警数"
          value={stats?.total_alerts || 0}
          subtitle="累计检测"
          icon={AlertTriangle}
          color="orange"
        />
        <StatCard
          title="未处理"
          value={unresolvedAlerts.length}
          subtitle="待处理告警"
          icon={AlertCircle}
          color="red"
        />
        <StatCard
          title="已处理"
          value={alerts.filter(a => a.resolved).length}
          subtitle="已解决告警"
          icon={CheckCircle}
          color="green"
        />
        <StatCard
          title="检测包数"
          value={formatNumber(stats?.total_packets_checked || 0)}
          subtitle="已分析数据包"
          icon={Shield}
          color="blue"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">告警趋势</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={alertTrendData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="alerts" stroke="#ef4444" strokeWidth={2} name="新增告警" />
              <Line type="monotone" dataKey="resolved" stroke="#22c55e" strokeWidth={2} name="已处理" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">严重程度分布</h3>
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

      <div className="card">
        <h3 className="text-lg font-semibold mb-4">攻击类型分布</h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={typeData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip content={({ active, payload }) => {
              if (active && payload && payload.length) {
                return (
                  <div className="bg-white p-2 border border-gray-200 rounded shadow">
                    <p className="font-medium">{payload[0].payload.fullName}</p>
                    <p className="text-sm text-gray-600">数量: {payload[0].value}</p>
                  </div>
                );
              }
              return null;
            }} />
            <Bar dataKey="value" fill="#0ea5e9" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">告警列表</h3>
          <div className="flex items-center space-x-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="搜索告警..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input pl-10 w-64"
              />
            </div>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="input w-32"
            >
              <option value="ALL">所有级别</option>
              <option value="LOW">低</option>
              <option value="MEDIUM">中</option>
              <option value="HIGH">高</option>
              <option value="CRITICAL">严重</option>
            </select>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="input w-40"
            >
              <option value="ALL">所有类型</option>
              <option value="port_scan">端口扫描</option>
              <option value="syn_flood">SYN泛洪</option>
              <option value="udp_flood">UDP泛洪</option>
              <option value="sql_injection">SQL注入</option>
              <option value="xss_attack">XSS攻击</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead>
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">时间</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">严重程度</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">类型</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">消息</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">源IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">目的IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">协议</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {unresolvedAlerts.slice(0, 20).map((alert) => (
                <tr key={alert.id} className="hover:bg-gray-50 cursor-pointer" onClick={() => setSelectedAlert(alert)}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatDate(alert.timestamp)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span className={`badge ${getSeverityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {alert.type}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900 max-w-xs truncate">
                    {alert.message}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {alert.source_ip || '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {alert.dest_ip || '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span className={`badge ${getProtocolColor(alert.protocol || 'UNKNOWN')}`}>
                      {alert.protocol || '-'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    {alert.resolved ? (
                      <span className="badge badge-success">已处理</span>
                    ) : (
                      <span className="badge badge-danger">未处理</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <div className="flex items-center space-x-2">
                      {!alert.resolved && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleResolveAlert(alert.id);
                          }}
                          className="text-gray-400 hover:text-green-600 transition-colors"
                          title="标记为已处理"
                        >
                          <CheckCircle className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {unresolvedAlerts.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            没有未处理的告警
          </div>
        )}
      </div>

      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onResolve={() => {
            handleResolveAlert(selectedAlert.id);
            setSelectedAlert(null);
          }}
        />
      )}
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle: string;
  icon: React.ElementType;
  color: 'blue' | 'green' | 'orange' | 'red';
}

function StatCard({ title, value, subtitle, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    green: 'bg-green-100 text-green-600',
    orange: 'bg-orange-100 text-orange-600',
    red: 'bg-red-100 text-red-600',
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

interface AlertDetailModalProps {
  alert: Alert;
  onClose: () => void;
  onResolve: () => void;
}

function AlertDetailModal({ alert, onClose, onResolve }: AlertDetailModalProps) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-gray-900">告警详情</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
            >
              <XCircle className="w-6 h-6" />
            </button>
          </div>
        </div>

        <div className="p-6 space-y-4">
          <div className="flex items-center space-x-3">
            <span className={`badge ${getSeverityColor(alert.severity)}`}>
              {alert.severity}
            </span>
            <span className="text-sm text-gray-500">{alert.type}</span>
          </div>

          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-2">告警消息</h3>
            <p className="text-gray-900">{alert.message}</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h3 className="text-sm font-medium text-gray-700 mb-1">时间</h3>
              <p className="text-gray-900">{formatDate(alert.timestamp)}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-700 mb-1">状态</h3>
              <p className="text-gray-900">{alert.resolved ? '已处理' : '未处理'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-700 mb-1">源IP</h3>
              <p className="text-gray-900">{alert.source_ip || '-'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-700 mb-1">目的IP</h3>
              <p className="text-gray-900">{alert.dest_ip || '-'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-700 mb-1">协议</h3>
              <p className="text-gray-900">{alert.protocol || '-'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-700 mb-1">目的端口</h3>
              <p className="text-gray-900">{alert.dst_port || '-'}</p>
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200">
            <button
              onClick={onClose}
              className="btn btn-outline"
            >
              关闭
            </button>
            {!alert.resolved && (
              <button
                onClick={onResolve}
                className="btn btn-success flex items-center space-x-2"
              >
                <CheckCircle className="w-4 h-4" />
                <span>标记为已处理</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function formatNumber(num: number): string {
  return new Intl.NumberFormat('zh-CN').format(num);
}

function getProtocolColor(protocol: string): string {
  const colors: Record<string, string> = {
    TCP: 'bg-blue-100 text-blue-800',
    UDP: 'bg-green-100 text-green-800',
    ICMP: 'bg-purple-100 text-purple-800',
    HTTP: 'bg-orange-100 text-orange-800',
    HTTPS: 'bg-indigo-100 text-indigo-800',
  };
  return colors[protocol] || 'bg-gray-100 text-gray-800';
}
