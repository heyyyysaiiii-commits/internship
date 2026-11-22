export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  category: string;
  severity: Severity;
  title: string;
  source: string;
  description: string;
  status: 'Open' | 'Investigating' | 'Resolved';
}

export interface ShadowRecord {
  timestamp: string;
  user: string;
  department: string;
  app_name: string;
  approved: string | boolean;
  data_sensitivity: string;
  action: string;
  records_shared: number;
}

export interface SocLog {
  timestamp: string;
  username: string;
  source_ip: string;
  event_type: string;
  status: string;
  destination_port: string | number;
  details: string;
}

export interface Finding {
  category: string;
  severity: Severity;
  evidence: string;
  explanation: string;
  recommendation: string;
}

export interface PromptAnalysis {
  score: number;
  level: RiskLevel | 'SAFE';
  findings: Finding[];
  verdict: string;
  maskedText: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  source: string;
  occurrences: number;
  reason: string;
  firstSeen: string;
  status: 'Open' | 'Investigating' | 'Resolved';
}
