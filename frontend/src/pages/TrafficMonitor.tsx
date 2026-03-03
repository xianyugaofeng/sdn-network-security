import React, { useState, useEffect } from 'react';
import { Activity, TrendingUp, Download, RefreshCw, Globe, Network } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell, AreaChart, Area } from 'recharts';
import { TrafficStats, TopTalker } from '../types';
import { trafficApi } from '../services/api';
import { formatBytes, formatNumber, formatDate } from '../lib/utils';

export default function TrafficMonitor() {
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [topTalkers, setTopTalkers] = useState<TopTalker[]>([]);
  const [recentFlows, setRecentFlows] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<'1h' | '6h' | '24h' | '7d'>('1h');

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const loadData = async () => {
    try {
      const [statsData, topTalkersData, flowsData] = await Promise.all([
        trafficApi.getStats(),
        trafficApi.getTopTalkers(10),
        trafficApi.getRecentFlows(300),
      ]);
      setStats(statsData);
      setTopTalkers(topTalkersData);
      setRecentFlows(flowsData);
    } catch (error) {
      console.error('Failed to load traffic data:', error);
    } finally {
      setLoading(false);
    }
  };

  const protocolData = stats?.protocol_distribution
    ? Object.entries(stats.protocol_distribution).map(([name, value]) => ({
        name,
        value: value as number,
      }))
    : [];

  const portData = stats?.port_distribution
    ? Object.entries(stats.port_distribution)
        .sort(([, a], [, b]) => (b as number) - (a as number))
        .slice(0, 10)
        .map(([name, value]) => ({
          name: `端口 ${name}`,
          value: value as number,
        }))
    : [];

  const trafficTrendData = [
    { time: '00:00', inbound: 45, outbound: 32 },
    { time: '04:00', inbound: 30, outbound: 25 },
    { time: '08:00', inbound: 95, outbound: 70 },
    { time: '12:00', inbound: 120, outbound: 95 },
    { time: '16:00', inbound: 105, outbound: 85 },
    { time: '20:00', inbound: 75, outbound: 60 },
    { time: '24:00', inbound: 55, outbound: 40 },
  ];

  const COLORS = ['#0ea5e9', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6'];

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
          <h1 className="text-2xl font-bold text-gray-900">流量监控</h1>
          <p className="text-gray-600 mt-1">实时监控网络流量和统计信息</p>
        </div>
        <div className="flex items-center space-x-3">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value as any)}
            className="input w-32"
          >
            <option value="1h">1小时</option>
            <option value="6h">6小时</option>
            <option value="24h">24小时</option>
            <option value="7d">7天</option>
          </select>
          <button
            onClick={loadData}
            className="btn btn-outline flex items-center space-x-2"
          >
            <RefreshCw className="w-4 h-4" />
            <span>刷新</span>
          </button>
          <button className="btn btn-primary flex items-center space-x-2">
            <Download className="w-4 h-4" />
            <span>导出</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard
          title="总流量"
          value={formatBytes(stats?.bandwidth_usage || 0) + '/s'}
          subtitle="实时带宽"
          icon={TrendingUp}
          color="blue"
        />
        <StatCard
          title="活跃流"
          value={formatNumber(stats?.total_flows || 0)}
          subtitle="当前连接数"
          icon={Activity}
          color="green"
        />
        <StatCard
          title="唯一流"
          value={formatNumber(stats?.total_unique_flows || 0)}
          subtitle="不同会话"
          icon={Network}
          color="purple"
        />
        <StatCard
          title="协议类型"
          value={Object.keys(stats?.protocol_distribution || {}).length}
          subtitle="检测到的协议"
          icon={Globe}
          color="orange"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">流量趋势</h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={trafficTrendData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Area type="monotone" dataKey="inbound" stackId="1" stroke="#0ea5e9" fill="#0ea5e9" fillOpacity={0.6} name="入站" />
              <Area type="monotone" dataKey="outbound" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.6} name="出站" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">协议分布</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={protocolData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {protocolData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">端口使用排行</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={portData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" />
              <YAxis dataKey="name" type="category" width={80} />
              <Tooltip />
              <Bar dataKey="value" fill="#0ea5e9" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">流量最多的主机</h3>
          <div className="space-y-3">
            {topTalkers.slice(0, 5).map((talker, index) => (
              <div key={talker.ip} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                    index < 3 ? 'bg-primary-100 text-primary-700' : 'bg-gray-200 text-gray-700'
                  }`}>
                    {index + 1}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">{talker.ip}</p>
                    <p className="text-xs text-gray-500">{formatNumber(talker.packets)} 包</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium text-gray-900">{formatBytes(talker.bytes)}</p>
                  <p className="text-xs text-gray-500">总流量</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold mb-4">最近流量</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead>
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">时间</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">源IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">源端口</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">目的IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">目的端口</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">协议</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">包大小</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {recentFlows.slice(0, 10).map((flow, index) => (
                <tr key={index} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatDate(flow.timestamp)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {flow.ip_src}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {flow.tp_src || '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {flow.ip_dst}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {flow.tp_dst || '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span className={`badge ${getProtocolColor(flow.protocol)}`}>
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatBytes(flow.packet_length)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle: string;
  icon: React.ElementType;
  color: 'blue' | 'green' | 'purple' | 'orange';
}

function StatCard({ title, value, subtitle, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    green: 'bg-green-100 text-green-600',
    purple: 'bg-purple-100 text-purple-600',
    orange: 'bg-orange-100 text-orange-600',
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
