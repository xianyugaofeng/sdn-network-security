import React, { useState } from 'react';
import { Settings, Shield, Activity, AlertTriangle, Brain, Server, Save, RefreshCw, Bell, Lock, Database, Monitor } from 'lucide-react';

export default function Settings() {
  const [activeTab, setActiveTab] = useState<'general' | 'firewall' | 'traffic' | 'detection' | 'anomaly' | 'system'>('general');
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState('');

  const handleSave = async () => {
    setSaving(true);
    setSaveMessage('');
    
    setTimeout(() => {
      setSaving(false);
      setSaveMessage('设置已保存');
      setTimeout(() => setSaveMessage(''), 3000);
    }, 1000);
  };

  const tabs = [
    { id: 'general' as const, name: '通用设置', icon: Settings },
    { id: 'firewall' as const, name: '防火墙', icon: Shield },
    { id: 'traffic' as const, name: '流量监控', icon: Activity },
    { id: 'detection' as const, name: '入侵检测', icon: AlertTriangle },
    { id: 'anomaly' as const, name: '异常检测', icon: Brain },
    { id: 'system' as const, name: '系统', icon: Server },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">系统设置</h1>
          <p className="text-gray-600 mt-1">配置系统参数和模块选项</p>
        </div>
        <div className="flex items-center space-x-3">
          {saveMessage && (
            <div className="flex items-center space-x-2 text-green-600">
              <Save className="w-4 h-4" />
              <span className="text-sm">{saveMessage}</span>
            </div>
          )}
          <button
            onClick={handleSave}
            disabled={saving}
            className="btn btn-primary flex items-center space-x-2"
          >
            {saving ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>保存中...</span>
              </>
            ) : (
              <>
                <Save className="w-4 h-4" />
                <span>保存设置</span>
              </>
            )}
          </button>
        </div>
      </div>

      <div className="flex gap-6">
        <div className="w-64 flex-shrink-0">
          <nav className="space-y-1">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                    activeTab === tab.id
                      ? 'bg-primary-50 text-primary-700'
                      : 'text-gray-700 hover:bg-gray-100'
                  }`}
                >
                  <Icon className={`w-5 h-5 ${activeTab === tab.id ? 'text-primary-600' : 'text-gray-400'}`} />
                  <span>{tab.name}</span>
                </button>
              );
            })}
          </nav>
        </div>

        <div className="flex-1">
          {activeTab === 'general' && <GeneralSettings />}
          {activeTab === 'firewall' && <FirewallSettings />}
          {activeTab === 'traffic' && <TrafficSettings />}
          {activeTab === 'detection' && <DetectionSettings />}
          {activeTab === 'anomaly' && <AnomalySettings />}
          {activeTab === 'system' && <SystemSettings />}
        </div>
      </div>
    </div>
  );
}

function GeneralSettings() {
  return (
    <div className="card space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h2 className="text-lg font-semibold">通用设置</h2>
        <p className="text-sm text-gray-500 mt-1">配置系统基本参数</p>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">系统名称</label>
          <input type="text" defaultValue="SDN网络安全系统" className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">环境</label>
          <select className="input">
            <option value="production">生产环境</option>
            <option value="staging">测试环境</option>
            <option value="development">开发环境</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">日志级别</label>
          <select className="input">
            <option value="DEBUG">DEBUG</option>
            <option value="INFO">INFO</option>
            <option value="WARNING">WARNING</option>
            <option value="ERROR">ERROR</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">调试模式</h3>
            <p className="text-xs text-gray-500">启用详细的调试日志</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>
      </div>
    </div>
  );
}

function FirewallSettings() {
  return (
    <div className="card space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h2 className="text-lg font-semibold">防火墙设置</h2>
        <p className="text-sm text-gray-500 mt-1">配置防火墙模块参数</p>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用防火墙</h3>
            <p className="text-xs text-gray-500">启用或禁用防火墙功能</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" defaultChecked className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">默认策略</label>
          <select className="input">
            <option value="ALLOW">允许</option>
            <option value="DENY">阻止</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">规则更新间隔（秒）</label>
          <input type="number" defaultValue={5} min={1} max={60} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">最大规则数</label>
          <input type="number" defaultValue={10000} min={100} max={100000} className="input" />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用黑名单</h3>
            <p className="text-xs text-gray-500">启用IP黑名单功能</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" defaultChecked className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用白名单</h3>
            <p className="text-xs text-gray-500">启用IP白名单功能</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" defaultChecked className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">黑名单TTL（秒）</label>
          <input type="number" defaultValue={3600} min={60} max={86400} className="input" />
        </div>
      </div>
    </div>
  );
}

function TrafficSettings() {
  return (
    <div className="card space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h2 className="text-lg font-semibold">流量监控设置</h2>
        <p className="text-sm text-gray-500 mt-1">配置流量监控模块参数</p>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用流量监控</h3>
            <p className="text-xs text-gray-500">启用或禁用流量监控功能</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" defaultChecked className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">采集间隔（秒）</label>
          <input type="number" defaultValue={10} min={1} max={300} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">最大流数量</label>
          <input type="number" defaultValue={10000} min={1000} max={100000} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">时间窗口（秒）</label>
          <input type="number" defaultValue={3600} min={60} max={86400} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">导出间隔（秒）</label>
          <input type="number" defaultValue={300} min={60} max={3600} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">导出格式</label>
          <select className="input">
            <option value="json">JSON</option>
            <option value="csv">CSV</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">带宽阈值（Mbps）</label>
          <input type="number" defaultValue={1000} min={100} max={10000} className="input" />
        </div>
      </div>
    </div>
  );
}

function DetectionSettings() {
  return (
    <div className="card space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h2 className="text-lg font-semibold">入侵检测设置</h2>
        <p className="text-sm text-gray-500 mt-1">配置入侵检测模块参数</p>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用入侵检测</h3>
            <p className="text-xs text-gray-500">启用或禁用入侵检测功能</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" defaultChecked className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">检测间隔（秒）</label>
          <input type="number" defaultValue={5} min={1} max={60} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">告警阈值（0-1）</label>
          <input type="number" defaultValue={0.5} min={0} max={1} step={0.1} className="input" />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">使用Snort规则</h3>
            <p className="text-xs text-gray-500">集成Snort规则库</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用内置规则</h3>
            <p className="text-xs text-gray-500">使用内置攻击特征库</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" defaultChecked className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用自定义规则</h3>
            <p className="text-xs text-gray-500">允许用户添加自定义规则</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" defaultChecked className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">告警保留天数</label>
          <input type="number" defaultValue={30} min={1} max={365} className="input" />
        </div>
      </div>
    </div>
  );
}

function AnomalySettings() {
  return (
    <div className="card space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h2 className="text-lg font-semibold">异常检测设置</h2>
        <p className="text-sm text-gray-500 mt-1">配置异常检测模块参数</p>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用异常检测</h3>
            <p className="text-xs text-gray-500">启用或禁用异常检测功能</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" defaultChecked className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">检测间隔（秒）</label>
          <input type="number" defaultValue={60} min={10} max={600} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">聚类数量（K）</label>
          <input type="number" defaultValue={3} min={2} max={10} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">最大迭代次数</label>
          <input type="number" defaultValue={100} min={10} max={1000} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">异常阈值（标准差倍数）</label>
          <input type="number" defaultValue={3.0} min={1.0} max={5.0} step={0.5} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">训练窗口（秒）</label>
          <input type="number" defaultValue={300} min={60} max={3600} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">特征归一化方法</label>
          <select className="input">
            <option value="minmax">Min-Max</option>
            <option value="zscore">Z-Score</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">敏感度</label>
          <select className="input">
            <option value="low">低</option>
            <option value="medium">中</option>
            <option value="high">高</option>
          </select>
        </div>
      </div>
    </div>
  );
}

function SystemSettings() {
  return (
    <div className="card space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h2 className="text-lg font-semibold">系统设置</h2>
        <p className="text-sm text-gray-500 mt-1">配置系统级参数</p>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">API服务器地址</label>
          <input type="text" defaultValue="http://localhost:5000" className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">API端口</label>
          <input type="number" defaultValue={5000} min={1024} max={65535} className="input" />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用SSL</h3>
            <p className="text-xs text-gray-500">使用HTTPS加密通信</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">工作线程数</label>
          <input type="number" defaultValue={4} min={1} max={16} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">数据包处理超时（秒）</label>
          <input type="number" defaultValue={1} min={0.1} max={10} step={0.1} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">流过期时间（秒）</label>
          <input type="number" defaultValue={600} min={60} max={3600} className="input" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">缓存TTL（秒）</label>
          <input type="number" defaultValue={300} min={60} max={3600} className="input" />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700">启用速率限制</h3>
            <p className="text-xs text-gray-500">限制API请求频率</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" defaultChecked className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">速率限制（请求/分钟）</label>
          <input type="number" defaultValue={1000} min={100} max={10000} className="input" />
        </div>
      </div>
    </div>
  );
}
