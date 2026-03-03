import React, { useState, useEffect } from 'react';
import { Shield, Plus, Trash2, Edit2, ToggleLeft, ToggleRight, Search, Filter, Ban, CheckCircle } from 'lucide-react';
import { FirewallRule, FirewallStats } from '../types';
import { firewallApi } from '../services/api';
import { formatDate } from '../lib/utils';

export default function Firewall() {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [stats, setStats] = useState<FirewallStats | null>(null);
  const [blacklist, setBlacklist] = useState<string[]>([]);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingRule, setEditingRule] = useState<FirewallRule | null>(null);
  const [activeTab, setActiveTab] = useState<'rules' | 'blacklist' | 'whitelist'>('rules');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterProtocol, setFilterProtocol] = useState<string>('ALL');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [rulesData, statsData, blacklistData, whitelistData] = await Promise.all([
        firewallApi.getRules(),
        firewallApi.getStats(),
        firewallApi.getBlacklist(),
        firewallApi.getWhitelist(),
      ]);
      setRules(rulesData);
      setStats(statsData);
      setBlacklist(blacklistData);
      setWhitelist(whitelistData);
    } catch (error) {
      console.error('Failed to load firewall data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleRule = async (id: number, enabled: boolean) => {
    try {
      await firewallApi.toggleRule(id, enabled);
      setRules(rules.map(rule => rule.id === id ? { ...rule, enabled } : rule));
    } catch (error) {
      console.error('Failed to toggle rule:', error);
    }
  };

  const handleDeleteRule = async (id: number) => {
    if (window.confirm('确定要删除这条规则吗？')) {
      try {
        await firewallApi.deleteRule(id);
        setRules(rules.filter(rule => rule.id !== id));
      } catch (error) {
        console.error('Failed to delete rule:', error);
      }
    }
  };

  const handleAddToBlacklist = async (ip: string) => {
    try {
      await firewallApi.addToBlacklist(ip);
      setBlacklist([...blacklist, ip]);
    } catch (error) {
      console.error('Failed to add to blacklist:', error);
    }
  };

  const handleRemoveFromBlacklist = async (ip: string) => {
    try {
      await firewallApi.removeFromBlacklist(ip);
      setBlacklist(blacklist.filter(item => item !== ip));
    } catch (error) {
      console.error('Failed to remove from blacklist:', error);
    }
  };

  const handleAddToWhitelist = async (ip: string) => {
    try {
      await firewallApi.addToWhitelist(ip);
      setWhitelist([...whitelist, ip]);
    } catch (error) {
      console.error('Failed to add to whitelist:', error);
    }
  };

  const handleRemoveFromWhitelist = async (ip: string) => {
    try {
      await firewallApi.removeFromWhitelist(ip);
      setWhitelist(whitelist.filter(item => item !== ip));
    } catch (error) {
      console.error('Failed to remove from whitelist:', error);
    }
  };

  const filteredRules = rules.filter(rule => {
    const matchesSearch = rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.src_ip?.includes(searchTerm) ||
                         rule.dst_ip?.includes(searchTerm);
    const matchesProtocol = filterProtocol === 'ALL' || rule.protocol === filterProtocol;
    return matchesSearch && matchesProtocol;
  });

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
          <h1 className="text-2xl font-bold text-gray-900">防火墙管理</h1>
          <p className="text-gray-600 mt-1">管理防火墙规则、黑名单和白名单</p>
        </div>
        {activeTab === 'rules' && (
          <button
            onClick={() => setShowAddModal(true)}
            className="btn btn-primary flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>添加规则</span>
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard title="总规则数" value={stats?.total_rules || 0} icon={Shield} color="blue" />
        <StatCard title="活跃规则" value={stats?.active_rules || 0} icon={CheckCircle} color="green" />
        <StatCard title="黑名单" value={blacklist.length} icon={Ban} color="red" />
        <StatCard title="白名单" value={whitelist.length} icon={CheckCircle} color="purple" />
      </div>

      <div className="card">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            <button
              onClick={() => setActiveTab('rules')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'rules'
                  ? 'border-primary-500 text-primary-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              防火墙规则
            </button>
            <button
              onClick={() => setActiveTab('blacklist')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'blacklist'
                  ? 'border-primary-500 text-primary-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              黑名单 ({blacklist.length})
            </button>
            <button
              onClick={() => setActiveTab('whitelist')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'whitelist'
                  ? 'border-primary-500 text-primary-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              白名单 ({whitelist.length})
            </button>
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'rules' && (
            <>
              <div className="flex items-center space-x-4 mb-6">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="搜索规则..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="input pl-10"
                  />
                </div>
                <select
                  value={filterProtocol}
                  onChange={(e) => setFilterProtocol(e.target.value)}
                  className="input w-40"
                >
                  <option value="ALL">所有协议</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="ICMP">ICMP</option>
                </select>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead>
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">规则名称</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">协议</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">源IP</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">目的IP</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">端口</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">动作</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">优先级</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {filteredRules.map((rule) => (
                      <tr key={rule.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {rule.name}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          <span className={`badge ${getProtocolColor(rule.protocol)}`}>
                            {rule.protocol}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {rule.src_ip || '-'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {rule.dst_ip || '-'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {rule.dst_port || '-'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <span className={`badge ${rule.action === 'ALLOW' ? 'badge-success' : 'badge-danger'}`}>
                            {rule.action === 'ALLOW' ? '允许' : '阻止'}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {rule.priority}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <button
                            onClick={() => handleToggleRule(rule.id, !rule.enabled)}
                            className="text-gray-400 hover:text-primary-600 transition-colors"
                          >
                            {rule.enabled ? (
                              <ToggleRight className="w-5 h-5 text-green-500" />
                            ) : (
                              <ToggleLeft className="w-5 h-5 text-gray-400" />
                            )}
                          </button>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <div className="flex items-center space-x-2">
                            <button
                              onClick={() => setEditingRule(rule)}
                              className="text-gray-400 hover:text-primary-600 transition-colors"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleDeleteRule(rule.id)}
                              className="text-gray-400 hover:text-red-600 transition-colors"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeTab === 'blacklist' && (
            <IPList
              title="黑名单"
              ips={blacklist}
              onAdd={handleAddToBlacklist}
              onRemove={handleRemoveFromBlacklist}
              color="red"
            />
          )}

          {activeTab === 'whitelist' && (
            <IPList
              title="白名单"
              ips={whitelist}
              onAdd={handleAddToWhitelist}
              onRemove={handleRemoveFromWhitelist}
              color="green"
            />
          )}
        </div>
      </div>

      {showAddModal && (
        <RuleModal
          onClose={() => setShowAddModal(false)}
          onSave={loadData}
        />
      )}

      {editingRule && (
        <RuleModal
          rule={editingRule}
          onClose={() => setEditingRule(null)}
          onSave={loadData}
        />
      )}
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: number;
  icon: React.ElementType;
  color: 'blue' | 'green' | 'red' | 'purple';
}

function StatCard({ title, value, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    green: 'bg-green-100 text-green-600',
    red: 'bg-red-100 text-red-600',
    purple: 'bg-purple-100 text-purple-600',
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}

interface IPListProps {
  title: string;
  ips: string[];
  onAdd: (ip: string) => void;
  onRemove: (ip: string) => void;
  color: 'red' | 'green';
}

function IPList({ title, ips, onAdd, onRemove, color }: IPListProps) {
  const [newIP, setNewIP] = useState('');

  const handleAdd = () => {
    if (newIP && !ips.includes(newIP)) {
      onAdd(newIP);
      setNewIP('');
    }
  };

  return (
    <div>
      <div className="flex items-center space-x-4 mb-6">
        <input
          type="text"
          placeholder="输入IP地址..."
          value={newIP}
          onChange={(e) => setNewIP(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleAdd()}
          className="input flex-1"
        />
        <button
          onClick={handleAdd}
          className={`btn ${color === 'red' ? 'btn-danger' : 'btn-success'}`}
        >
          添加
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {ips.map((ip) => (
          <div
            key={ip}
            className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
          >
            <span className="text-sm font-medium text-gray-900">{ip}</span>
            <button
              onClick={() => onRemove(ip)}
              className="text-gray-400 hover:text-red-600 transition-colors"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        ))}
      </div>

      {ips.length === 0 && (
        <div className="text-center py-12 text-gray-500">
          暂无IP地址
        </div>
      )}
    </div>
  );
}

interface RuleModalProps {
  rule?: FirewallRule;
  onClose: () => void;
  onSave: () => void;
}

function RuleModal({ rule, onClose, onSave }: RuleModalProps) {
  const [formData, setFormData] = useState({
    name: rule?.name || '',
    action: rule?.action || 'ALLOW',
    protocol: rule?.protocol || 'TCP',
    src_ip: rule?.src_ip || '',
    dst_ip: rule?.dst_ip || '',
    src_port: rule?.src_port || '',
    dst_port: rule?.dst_port || '',
    priority: rule?.priority || 50,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (rule) {
        await firewallApi.updateRule(rule.id, formData);
      } else {
        await firewallApi.addRule({
          ...formData,
          enabled: true,
          created_at: new Date().toISOString(),
        } as any);
      }
      onSave();
      onClose();
    } catch (error) {
      console.error('Failed to save rule:', error);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-xl font-bold text-gray-900">
            {rule ? '编辑规则' : '添加规则'}
          </h2>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">规则名称</label>
            <input
              type="text"
              required
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="input"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">动作</label>
              <select
                value={formData.action}
                onChange={(e) => setFormData({ ...formData, action: e.target.value as any })}
                className="input"
              >
                <option value="ALLOW">允许</option>
                <option value="DENY">阻止</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">协议</label>
              <select
                value={formData.protocol}
                onChange={(e) => setFormData({ ...formData, protocol: e.target.value as any })}
                className="input"
              >
                <option value="ALL">ALL</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">源IP</label>
              <input
                type="text"
                placeholder="例如: 192.168.1.1"
                value={formData.src_ip}
                onChange={(e) => setFormData({ ...formData, src_ip: e.target.value })}
                className="input"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">目的IP</label>
              <input
                type="text"
                placeholder="例如: 192.168.1.2"
                value={formData.dst_ip}
                onChange={(e) => setFormData({ ...formData, dst_ip: e.target.value })}
                className="input"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">源端口</label>
              <input
                type="number"
                placeholder="例如: 80"
                value={formData.src_port}
                onChange={(e) => setFormData({ ...formData, src_port: parseInt(e.target.value) || undefined })}
                className="input"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">目的端口</label>
              <input
                type="number"
                placeholder="例如: 443"
                value={formData.dst_port}
                onChange={(e) => setFormData({ ...formData, dst_port: parseInt(e.target.value) || undefined })}
                className="input"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">优先级 (1-100)</label>
            <input
              type="number"
              min="1"
              max="100"
              required
              value={formData.priority}
              onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) })}
              className="input"
            />
            <p className="text-xs text-gray-500 mt-1">数值越大优先级越高</p>
          </div>

          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn btn-outline"
            >
              取消
            </button>
            <button
              type="submit"
              className="btn btn-primary"
            >
              保存
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function getProtocolColor(protocol: string): string {
  const colors: Record<string, string> = {
    TCP: 'bg-blue-100 text-blue-800',
    UDP: 'bg-green-100 text-green-800',
    ICMP: 'bg-purple-100 text-purple-800',
    ALL: 'bg-gray-100 text-gray-800',
  };
  return colors[protocol] || 'bg-gray-100 text-gray-800';
}
