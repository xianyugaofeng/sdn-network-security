import React, { useState, useEffect } from 'react';
import { Brain, Activity, RefreshCw, CheckCircle, XCircle, Search, Filter, AlertCircle, Scatter } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, ScatterChart, Scatter, ZAxis } from 'recharts';
import { Anomaly, AnomalyStats } from '../types';
import { anomalyApi } from '../services/api';
import { formatDate, getSeverityColor } from '../lib/utils';

export default function AnomalyDetection() {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [stats, setStats] = useState<AnomalyStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [filterSeverity]);

  const loadData = async () => {
    try {
      const [anomaliesData, statsData] = await Promise.all([
        anomalyApi.getAnomalies(100),
        anomalyApi.getStats(),
      ]);
      setAnomalies(anomaliesData);
      setStats(statsData);
    } catch (error) {
      console.error('Failed to load anomaly data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleResolveAnomaly = async (id: string) => {
    try {
      await anomalyApi.resolveAnomaly(id);
      setAnomalies(anomalies.map(anomaly => 
        anomaly.id === id ? { ...anomaly, resolved: true } : anomaly
      ));
    } catch (error) {
      console.error('Failed to resolve anomaly:', error);
    }
  };

  const severityData = stats?.anomalies_by_type
    ? Object.entries(stats.anomalies_by_type).map(([name, value]) => ({
        name,
        value: value as number,
      }))
    : [];

  const anomalyTrendData = [
    { time: '00:00', anomalies: 8, detected: 7 },
    { time: '04:00', anomalies: 5, detected: 5 },
    { time: '08:00', anomalies: 15, detected: 14 },
    { time: '12:00', anomalies: 22, detected: 20 },
    { time: '16:00', anomalies: 18, detected: 17 },
    { time: '20:00', anomalies: 12, detected: 11 },
    { time: '24:00', anomalies: 10, detected: 9 },
  ];

  const clusterData = Array.from({ length: 50 }, (_, i) => ({
    x: Math.random() * 100,
    y: Math.random() * 100,
    z: Math.random() * 10,
  }));

  const COLORS = ['#0ea5e9', '#f59e0b', '#ef4444'];

  const filteredAnomalies = anomalies.filter(anomaly => {
    const matchesSeverity = filterSeverity === 'ALL' || anomaly.severity === filterSeverity;
    const matchesSearch = !searchTerm || 
      anomaly.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      anomaly.flow_info.src_ip?.includes(searchTerm) ||
      anomaly.flow_info.dst_ip?.includes(searchTerm);
    return matchesSeverity && matchesSearch;
  });

  const unresolvedAnomalies = filteredAnomalies.filter(anomaly => !anomaly.resolved);

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
          <h1 className="text-2xl font-bold text-gray-900">异常检测</h1>
          <p className="text-gray-600 mt-1">基于机器学习的流量异常识别</p>
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
          title="分析流数"
          value={formatNumber(stats?.total_flows_analyzed || 0)}
          subtitle="已分析流量"
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="检测异常"
          value={stats?.total_anomalies || 0}
          subtitle="累计异常"
          icon={Brain}
          color="purple"
        />
        <StatCard
          title="未处理"
          value={unresolvedAnomalies.length}
          subtitle="待处理异常"
          icon={AlertCircle}
          color="orange"
        />
        <StatCard
          title="聚类数"
          value={stats?.clusters || 3}
          subtitle="K-means聚类"
          icon={Scatter}
          color="green"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">异常趋势</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={anomalyTrendData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="anomalies" stroke="#ef4444" strokeWidth={2} name="总异常" />
              <Line type="monotone" dataKey="detected" stroke="#0ea5e9" strokeWidth={2} name="已检测" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">聚类可视化</h3>
          <ResponsiveContainer width="100%" height={300}>
            <ScatterChart>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="x" name="特征1" />
              <YAxis dataKey="y" name="特征2" />
              <ZAxis dataKey="z" range={[50, 400]} name="异常分数" />
              <Tooltip cursor={{ strokeDasharray: '3 3' }} />
              <Scatter data={clusterData} fill="#0ea5e9" />
            </ScatterChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold mb-4">异常类型分布</h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={severityData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Bar dataKey="value" fill="#0ea5e9" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">异常列表</h3>
          <div className="flex items-center space-x-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="搜索异常..."
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
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">异常分数</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">阈值</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">源IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">目的IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">协议</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {unresolvedAnomalies.slice(0, 20).map((anomaly) => (
                <tr key={anomaly.id} className="hover:bg-gray-50 cursor-pointer" onClick={() => setSelectedAnomaly(anomaly)}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatDate(anomaly.timestamp)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span className={`badge ${getSeverityColor(anomaly.severity)}`}>
                      {anomaly.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {anomaly.type}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {anomaly.anomaly_score.toFixed(2)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {anomaly.threshold.toFixed(2)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {anomaly.flow_info.src_ip || '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {anomaly.flow_info.dst_ip || '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span className={`badge ${getProtocolColor(anomaly.flow_info.protocol || 'UNKNOWN')}`}>
                      {anomaly.flow_info.protocol || '-'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    {anomaly.resolved ? (
                      <span className="badge badge-success">已处理</span>
                    ) : (
                      <span className="badge badge-danger">未处理</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <div className="flex items-center space-x-2">
                      {!anomaly.resolved && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleResolveAnomaly(anomaly.id);
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

        {unresolvedAnomalies.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            没有未处理的异常
          </div>
        )}
      </div>

      {selectedAnomaly && (
        <AnomalyDetailModal
          anomaly={selectedAnomaly}
          onClose={() => setSelectedAnomaly(null)}
          onResolve={() => {
            handleResolveAnomaly(selectedAnomaly.id);
            setSelectedAnomaly(null);
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
  color: 'blue' | 'green' | 'orange' | 'purple';
}

function StatCard({ title, value, subtitle, icon: Icon, color }: StatCardProps) {
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

interface AnomalyDetailModalProps {
  anomaly: Anomaly;
  onClose: () => void;
  onResolve: () => void;
}

function AnomalyDetailModal({ anomaly, onClose, onResolve }: AnomalyDetailModalProps) {
  const severityPercentage = Math.min((anomaly.anomaly_score / anomaly.threshold) * 100, 100);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-gray-900">异常详情</h2>
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
            <span className={`badge ${getSeverityColor(anomaly.severity)}`}>
              {anomaly.severity}
            </span>
            <span className="text-sm text-gray-500">{anomaly.type}</span>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h3 className="text-sm font-medium text-gray-700 mb-1">异常分数</h3>
              <div className="flex items-center space-x-2">
                <span className="text-2xl font-bold text-gray-900">{anomaly.anomaly_score.toFixed(2)}</span>
                <span className="text-sm text-gray-500">/ {anomaly.threshold.toFixed(2)}</span>
              </div>
              <div className="w-full h-2 bg-gray-200 rounded-full mt-2 overflow-hidden">
                <div
                  className="h-full bg-primary-600 transition-all"
                  style={{ width: `${severityPercentage}%` }}
                />
              </div>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-700 mb-1">检测时间</h3>
              <p className="text-gray-900">{formatDate(anomaly.timestamp)}</p>
            </div>
          </div>

          <div className="border-t border-gray-200 pt-4">
            <h3 className="text-sm font-medium text-gray-700 mb-3">流信息</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <h3 className="text-xs font-medium text-gray-500 mb-1">源IP</h3>
                <p className="text-sm text-gray-900">{anomaly.flow_info.src_ip || '-'}</p>
              </div>
              <div>
                <h3 className="text-xs font-medium text-gray-500 mb-1">目的IP</h3>
                <p className="text-sm text-gray-900">{anomaly.flow_info.dst_ip || '-'}</p>
              </div>
              <div>
                <h3 className="text-xs font-medium text-gray-500 mb-1">协议</h3>
                <p className="text-sm text-gray-900">{anomaly.flow_info.protocol || '-'}</p>
              </div>
              <div>
                <h3 className="text-xs font-medium text-gray-500 mb-1">数据量</h3>
                <p className="text-sm text-gray-900">{anomaly.flow_info.bytes ? formatBytes(anomaly.flow_info.bytes) : '-'}</p>
              </div>
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200">
            <button
              onClick={onClose}
              className="btn btn-outline"
            >
              关闭
            </button>
            {!anomaly.resolved && (
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

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
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
