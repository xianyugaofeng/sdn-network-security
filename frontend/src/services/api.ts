import api from './api';
import {
  FirewallRule,
  FirewallStats,
  TrafficStats,
  TopTalker,
  Alert,
  DetectionStats,
  Anomaly,
  AnomalyStats,
  DashboardStats,
  SystemStatus,
} from '../types';

export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    const response = await api.get('/dashboard/stats');
    return response.data;
  },
};

export const firewallApi = {
  getRules: async (): Promise<FirewallRule[]> => {
    const response = await api.get('/firewall/rules');
    return response.data;
  },

  getStats: async (): Promise<FirewallStats> => {
    const response = await api.get('/firewall/stats');
    return response.data;
  },

  addRule: async (rule: Omit<FirewallRule, 'id' | 'created_at'>): Promise<FirewallRule> => {
    const response = await api.post('/firewall/rules', rule);
    return response.data;
  },

  updateRule: async (id: number, rule: Partial<FirewallRule>): Promise<FirewallRule> => {
    const response = await api.put(`/firewall/rules/${id}`, rule);
    return response.data;
  },

  deleteRule: async (id: number): Promise<void> => {
    await api.delete(`/firewall/rules/${id}`);
  },

  toggleRule: async (id: number, enabled: boolean): Promise<FirewallRule> => {
    const response = await api.patch(`/firewall/rules/${id}/toggle`, { enabled });
    return response.data;
  },

  getBlacklist: async (): Promise<string[]> => {
    const response = await api.get('/firewall/blacklist');
    return response.data;
  },

  addToBlacklist: async (ip: string): Promise<void> => {
    await api.post('/firewall/blacklist', { ip });
  },

  removeFromBlacklist: async (ip: string): Promise<void> => {
    await api.delete(`/firewall/blacklist/${ip}`);
  },

  getWhitelist: async (): Promise<string[]> => {
    const response = await api.get('/firewall/whitelist');
    return response.data;
  },

  addToWhitelist: async (ip: string): Promise<void> => {
    await api.post('/firewall/whitelist', { ip });
  },

  removeFromWhitelist: async (ip: string): Promise<void> => {
    await api.delete(`/firewall/whitelist/${ip}`);
  },
};

export const trafficApi = {
  getStats: async (): Promise<TrafficStats> => {
    const response = await api.get('/traffic/stats');
    return response.data;
  },

  getTopTalkers: async (limit: number = 10): Promise<TopTalker[]> => {
    const response = await api.get(`/traffic/top-talkers?limit=${limit}`);
    return response.data;
  },

  getRecentFlows: async (window: number = 300): Promise<any[]> => {
    const response = await api.get(`/traffic/flows?window=${window}`);
    return response.data;
  },
};

export const detectionApi = {
  getAlerts: async (limit: number = 50): Promise<Alert[]> => {
    const response = await api.get(`/detection/alerts?limit=${limit}`);
    return response.data;
  },

  getStats: async (): Promise<DetectionStats> => {
    const response = await api.get('/detection/stats');
    return response.data;
  },

  resolveAlert: async (id: string): Promise<void> => {
    await api.patch(`/detection/alerts/${id}/resolve`);
  },
};

export const anomalyApi = {
  getAnomalies: async (limit: number = 50): Promise<Anomaly[]> => {
    const response = await api.get(`/anomaly/anomalies?limit=${limit}`);
    return response.data;
  },

  getStats: async (): Promise<AnomalyStats> => {
    const response = await api.get('/anomaly/stats');
    return response.data;
  },

  resolveAnomaly: async (id: string): Promise<void> => {
    await api.patch(`/anomaly/anomalies/${id}/resolve`);
  },
};

export const systemApi = {
  getStatus: async (): Promise<SystemStatus> => {
    const response = await api.get('/system/status');
    return response.data;
  },
};
