export interface FirewallRule {
  id: number;
  name: string;
  action: 'ALLOW' | 'DENY';
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ALL';
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  priority: number;
  enabled: boolean;
  created_at: string;
}

export interface FirewallStats {
  total_rules: number;
  blacklist_size: number;
  whitelist_size: number;
  active_rules: number;
  timestamp: string;
}

export interface FlowInfo {
  timestamp: string;
  ip_src: string;
  ip_dst: string;
  tp_src?: number;
  tp_dst?: number;
  protocol: string;
  packet_length: number;
  tcp_flags?: number;
  ttl?: number;
  icmp_type?: number;
  payload?: string;
}

export interface TrafficStats {
  total_flows: number;
  total_unique_flows: number;
  protocol_distribution: Record<string, number>;
  port_distribution: Record<number, number>;
  bandwidth_usage: number;
  timestamp: string;
}

export interface TopTalker {
  ip: string;
  bytes: number;
  packets: number;
}

export interface Alert {
  id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  message: string;
  type: string;
  source_ip?: string;
  dest_ip?: string;
  protocol?: string;
  dst_port?: number;
  resolved: boolean;
}

export interface DetectionStats {
  total_packets_checked: number;
  total_alerts: number;
  alerts_by_type: Record<string, number>;
  alerts_by_severity: Record<string, number>;
  timestamp: string;
}

export interface Anomaly {
  id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  type: string;
  anomaly_score: number;
  threshold: number;
  flow_info: {
    src_ip?: string;
    dst_ip?: string;
    protocol?: string;
    bytes?: number;
  };
  resolved: boolean;
}

export interface AnomalyStats {
  total_flows_analyzed: number;
  total_anomalies: number;
  anomalies_by_type: Record<string, number>;
  clusters: number;
  timestamp: string;
}

export interface SystemStatus {
  controller_status: 'online' | 'offline' | 'error';
  switch_count: number;
  total_flows: number;
  cpu_usage: number;
  memory_usage: number;
  uptime: number;
}

export interface DashboardStats {
  firewall: FirewallStats;
  traffic: TrafficStats;
  detection: DetectionStats;
  anomaly: AnomalyStats;
  system: SystemStatus;
  recent_alerts: Alert[];
  recent_anomalies: Anomaly[];
}
