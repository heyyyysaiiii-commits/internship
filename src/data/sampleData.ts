import type { SecurityEvent, ShadowRecord, SocLog } from '../types';

export const sampleEvents: SecurityEvent[] = [
  { id: 'EVT-2401', timestamp: '2026-11-22T18:42:00', category: 'Prompt Injection', severity: 'Critical', title: 'System instruction override attempt', source: 'AI Gateway · analyst-04', description: 'Prompt attempted to override system instructions and extract hidden context.', status: 'Open' },
  { id: 'EVT-2398', timestamp: '2026-11-22T18:31:00', category: 'Data Leakage', severity: 'High', title: 'Credential-like value in prompt', source: 'AI Guardrails · engineering', description: 'A token-shaped string was found in a prompt submitted for inspection.', status: 'Investigating' },
  { id: 'EVT-2391', timestamp: '2026-11-22T18:14:00', category: 'Shadow AI', severity: 'High', title: 'Unapproved AI application usage', source: 'Usage sample · product', description: 'An unapproved external assistant was used with confidential data classification.', status: 'Open' },
  { id: 'EVT-2387', timestamp: '2026-11-22T17:56:00', category: 'Authentication', severity: 'Medium', title: 'Repeated authentication failures', source: 'SOC log sample · 198.51.100.24', description: 'Multiple failed login events were correlated for one source address.', status: 'Investigating' },
  { id: 'EVT-2380', timestamp: '2026-11-22T17:25:00', category: 'Network', severity: 'Medium', title: 'Possible port enumeration', source: 'SOC log sample · 203.0.113.17', description: 'A source contacted several distinct destination ports in a short window.', status: 'Open' },
  { id: 'EVT-2372', timestamp: '2026-11-22T16:48:00', category: 'Data Leakage', severity: 'Low', title: 'Personal data pattern detected', source: 'Prompt inspection · support', description: 'An email address and phone-like value were detected and masked.', status: 'Resolved' },
  { id: 'EVT-2366', timestamp: '2026-11-22T16:20:00', category: 'AI Governance', severity: 'Low', title: 'New AI tool requires review', source: 'Usage sample · design', description: 'An application was observed that is not yet present in the approved tools list.', status: 'Open' },
];

export const sampleShadowRecords: ShadowRecord[] = [
  { timestamp: '2026-11-22T18:31:00', user: 'a.rao', department: 'Engineering', app_name: 'PublicChat AI', approved: 'false', data_sensitivity: 'Confidential', action: 'Prompt submitted', records_shared: 3 },
  { timestamp: '2026-11-22T18:02:00', user: 'm.shah', department: 'Marketing', app_name: 'Enterprise Copilot', approved: 'true', data_sensitivity: 'Public', action: 'Content generation', records_shared: 0 },
  { timestamp: '2026-11-22T17:44:00', user: 's.kumar', department: 'Finance', app_name: 'QuickLLM', approved: 'false', data_sensitivity: 'Internal', action: 'File uploaded', records_shared: 2 },
  { timestamp: '2026-11-22T17:18:00', user: 'n.iyer', department: 'Engineering', app_name: 'Code Assistant Enterprise', approved: 'true', data_sensitivity: 'Internal', action: 'Code completion', records_shared: 0 },
  { timestamp: '2026-11-22T16:51:00', user: 'p.das', department: 'HR', app_name: 'PublicChat AI', approved: 'false', data_sensitivity: 'Personal', action: 'Prompt submitted', records_shared: 1 },
  { timestamp: '2026-11-22T16:12:00', user: 'r.jones', department: 'Support', app_name: 'Enterprise Copilot', approved: 'true', data_sensitivity: 'Customer', action: 'Summarization', records_shared: 0 },
  { timestamp: '2026-11-22T15:40:00', user: 'k.patel', department: 'Product', app_name: 'SketchGen AI', approved: 'false', data_sensitivity: 'Public', action: 'Image generation', records_shared: 0 },
  { timestamp: '2026-11-22T15:05:00', user: 'v.nair', department: 'Finance', app_name: 'QuickLLM', approved: 'false', data_sensitivity: 'Confidential', action: 'Prompt submitted', records_shared: 5 },
  { timestamp: '2026-11-22T14:38:00', user: 'd.miller', department: 'Engineering', app_name: 'Code Assistant Enterprise', approved: 'true', data_sensitivity: 'Internal', action: 'Code completion', records_shared: 0 },
  { timestamp: '2026-11-22T14:10:00', user: 't.wilson', department: 'Legal', app_name: 'PublicChat AI', approved: 'false', data_sensitivity: 'Confidential', action: 'Document pasted', records_shared: 1 },
  { timestamp: '2026-11-22T13:52:00', user: 'e.gupta', department: 'Marketing', app_name: 'Enterprise Copilot', approved: 'true', data_sensitivity: 'Public', action: 'Content generation', records_shared: 0 },
  { timestamp: '2026-11-22T13:20:00', user: 'b.lee', department: 'HR', app_name: 'NoteBot', approved: 'false', data_sensitivity: 'Personal', action: 'Meeting notes', records_shared: 2 },
];

export const sampleSocLogs: SocLog[] = [
  { timestamp: '2026-11-22T18:10:00', username: 'jsmith', source_ip: '198.51.100.24', event_type: 'login', status: 'failed', destination_port: '443', details: 'Invalid password' },
  { timestamp: '2026-11-22T18:10:24', username: 'jsmith', source_ip: '198.51.100.24', event_type: 'login', status: 'failed', destination_port: '443', details: 'Invalid password' },
  { timestamp: '2026-11-22T18:10:49', username: 'jsmith', source_ip: '198.51.100.24', event_type: 'login', status: 'failed', destination_port: '443', details: 'Invalid password' },
  { timestamp: '2026-11-22T18:11:06', username: 'jsmith', source_ip: '198.51.100.24', event_type: 'login', status: 'failed', destination_port: '443', details: 'MFA challenge not completed' },
  { timestamp: '2026-11-22T17:55:00', username: 'svc-backup', source_ip: '203.0.113.17', event_type: 'connection', status: 'allowed', destination_port: '21', details: 'Connection attempt' },
  { timestamp: '2026-11-22T17:55:03', username: 'svc-backup', source_ip: '203.0.113.17', event_type: 'connection', status: 'allowed', destination_port: '22', details: 'Connection attempt' },
  { timestamp: '2026-11-22T17:55:06', username: 'svc-backup', source_ip: '203.0.113.17', event_type: 'connection', status: 'allowed', destination_port: '23', details: 'Connection attempt' },
  { timestamp: '2026-11-22T17:55:08', username: 'svc-backup', source_ip: '203.0.113.17', event_type: 'connection', status: 'allowed', destination_port: '25', details: 'Connection attempt' },
  { timestamp: '2026-11-22T17:55:10', username: 'svc-backup', source_ip: '203.0.113.17', event_type: 'connection', status: 'allowed', destination_port: '80', details: 'Connection attempt' },
  { timestamp: '2026-11-22T17:55:12', username: 'svc-backup', source_ip: '203.0.113.17', event_type: 'connection', status: 'allowed', destination_port: '443', details: 'Connection attempt' },
  { timestamp: '2026-11-22T17:42:00', username: 'aroy', source_ip: '192.0.2.44', event_type: 'login', status: 'success', destination_port: '443', details: 'Normal SSO login' },
  { timestamp: '2026-11-22T17:28:00', username: 'admin', source_ip: '192.0.2.90', event_type: 'privilege_change', status: 'success', destination_port: '22', details: 'Administrative role granted outside change window' },
  { timestamp: '2026-11-22T16:58:00', username: 'mchen', source_ip: '192.0.2.51', event_type: 'login', status: 'failed', destination_port: '443', details: 'Invalid password' },
  { timestamp: '2026-11-22T16:51:00', username: 'mchen', source_ip: '192.0.2.51', event_type: 'login', status: 'failed', destination_port: '443', details: 'Invalid password' },
  { timestamp: '2026-11-22T16:30:00', username: 'api-worker', source_ip: '192.0.2.63', event_type: 'data_access', status: 'allowed', destination_port: '5432', details: 'Service account queried customer records' },
];
