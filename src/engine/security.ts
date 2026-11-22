import type { Finding, Incident, PromptAnalysis, RiskLevel, Severity, ShadowRecord, SocLog } from '../types';

const promptRules: Array<{ category: string; pattern: RegExp; severity: Severity; explanation: string; recommendation: string }> = [
  { category: 'Instruction override', pattern: /\b(ignore|disregard|override|forget)\b.{0,70}\b(previous|prior|above|system|developer|all)\b.{0,35}\b(instruction|prompt|rule|message)s?\b/i, severity: 'Critical', explanation: 'The text appears to instruct an AI system to ignore or replace higher-priority instructions.', recommendation: 'Treat the content as untrusted input. Preserve system/developer instruction boundaries and review the source.' },
  { category: 'System prompt extraction', pattern: /\b(reveal|show|print|dump|repeat|expose)\b.{0,55}\b(system prompt|hidden prompt|developer message|internal instruction|chain of thought)\b/i, severity: 'High', explanation: 'The prompt appears to request hidden instructions or internal model context.', recommendation: 'Do not disclose hidden instructions, secrets or internal reasoning. Return only approved user-facing information.' },
  { category: 'Jailbreak / policy bypass', pattern: /\b(jailbreak|DAN mode|developer mode|unrestricted mode|bypass (the )?(safety|policy|guardrails)|act as an? (unrestricted|uncensored))\b/i, severity: 'High', explanation: 'The text contains language commonly associated with attempts to bypass safety controls.', recommendation: 'Keep policy enforcement enabled and assess the request against the approved usage policy.' },
  { category: 'Untrusted instruction in content', pattern: /\b(new instruction|important:|do not tell the user|secretly|exfiltrate|send .* to|upload .* to)\b/i, severity: 'Medium', explanation: 'The text contains instruction-like or data-transfer language that may be unsafe depending on context.', recommendation: 'Separate quoted or retrieved content from trusted instructions and confirm any data-transfer request.' },
  { category: 'Credential / secret exposure', pattern: /\b(api[_ -]?key|access[_ -]?token|password|passwd|secret)\s*[:=]\s*[^\s,;]{6,}/i, severity: 'Critical', explanation: 'A credential-like assignment appears in the submitted text.', recommendation: 'Remove and rotate any real exposed secret. Do not send credentials to public AI services.' },
];

const sensitiveRules: Array<{ category: string; pattern: RegExp; severity: Severity; recommendation: string }> = [
  { category: 'Email address', pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, severity: 'Low', recommendation: 'Mask personal or business email addresses unless sharing is explicitly approved.' },
  { category: 'Phone number', pattern: /(?<!\w)(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3,5}\)?[\s-]?)\d{3,5}[\s-]?\d{3,5}(?!\w)/g, severity: 'Medium', recommendation: 'Remove or mask phone numbers before submitting content to an unapproved AI service.' },
  { category: 'Password / secret assignment', pattern: /\b(password|passwd|client_secret|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["']?[^\s"',;]{6,}/gi, severity: 'Critical', recommendation: 'Revoke and rotate exposed credentials; move secrets to a managed vault.' },
  { category: 'JWT token', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, severity: 'Critical', recommendation: 'Treat the token as compromised, revoke it and review associated access.' },
  { category: 'Private key material', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: 'Critical', recommendation: 'Remove private key material and rotate the key pair immediately if it was real.' },
  { category: 'Cloud access key pattern', pattern: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'Critical', recommendation: 'Revoke the access key, audit its use and replace it with scoped short-lived credentials.' },
  { category: 'National identifier pattern', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'High', recommendation: 'Mask personal identifiers and verify the applicable data-handling policy.' },
  { category: 'Source-code / database secret', pattern: /(?:mongodb(?:\+srv)?:\/\/[^\s]+|postgres(?:ql)?:\/\/[^\s]+|mysql:\/\/[^\s]+|BEGIN OPENSSH PRIVATE KEY)/gi, severity: 'High', recommendation: 'Remove connection strings and secrets from prompts; rotate any credential that may have been exposed.' },
];

const severityWeight: Record<Severity, number> = { Low: 12, Medium: 25, High: 40, Critical: 55 };

export function maskSensitive(text: string): string {
  let masked = text;
  for (const rule of sensitiveRules) {
    masked = masked.replace(rule.pattern, (value) => {
      if (value.length <= 6) return '••••';
      return `${value.slice(0, 2)}${'•'.repeat(Math.min(12, Math.max(4, value.length - 4)))}${value.slice(-2)}`;
    });
  }
  return masked;
}

export function analyzePrompt(text: string): PromptAnalysis {
  const findings: Finding[] = [];
  for (const rule of promptRules) {
    const match = text.match(rule.pattern);
    if (match) findings.push({ category: rule.category, severity: rule.severity, evidence: maskSensitive(match[0]), explanation: rule.explanation, recommendation: rule.recommendation });
  }
  for (const rule of sensitiveRules) {
    const matches = [...text.matchAll(new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`))];
    if (matches.length) findings.push({ category: rule.category, severity: rule.severity, evidence: `${matches.length} match${matches.length > 1 ? 'es' : ''} · ${maskSensitive(matches[0][0])}`, explanation: `Pattern-based inspection detected ${rule.category.toLowerCase()} data.`, recommendation: rule.recommendation });
  }
  const unique = findings.filter((item, index, arr) => arr.findIndex((other) => other.category === item.category) === index);
  const score = Math.min(100, unique.reduce((sum, finding) => sum + severityWeight[finding.severity], 0));
  const level: PromptAnalysis['level'] = score === 0 ? 'SAFE' : score >= 80 ? 'CRITICAL' : score >= 55 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW';
  const verdict = score === 0 ? 'No matching high-signal patterns detected' : level === 'CRITICAL' ? 'Do not submit · critical patterns detected' : level === 'HIGH' ? 'Review before submission' : 'Potential risk · inspect findings';
  return { score, level, findings: unique, verdict, maskedText: maskSensitive(text) };
}

export function detectSensitiveData(text: string): Finding[] {
  const findings: Finding[] = [];
  for (const rule of sensitiveRules) {
    const matches = [...text.matchAll(new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`))];
    if (matches.length) findings.push({ category: rule.category, severity: rule.severity, evidence: `${matches.length} match${matches.length > 1 ? 'es' : ''} · ${maskSensitive(matches[0][0])}`, explanation: `Detected ${matches.length} possible ${rule.category.toLowerCase()} pattern${matches.length > 1 ? 's' : ''}.`, recommendation: rule.recommendation });
  }
  return findings;
}

export function isApproved(value: string | boolean): boolean {
  return value === true || /^(true|yes|approved|1)$/i.test(String(value).trim());
}

export function analyzeShadow(records: ShadowRecord[]) {
  const unauthorized = records.filter((record) => !isApproved(record.approved));
  const sensitive = records.filter((record) => /confidential|personal|customer|restricted/i.test(record.data_sensitivity));
  const riskRecords = unauthorized.filter((record) => /confidential|personal|customer|restricted/i.test(record.data_sensitivity));
  const appCounts = records.reduce<Record<string, number>>((acc, item) => { acc[item.app_name] = (acc[item.app_name] || 0) + 1; return acc; }, {});
  const departmentCounts = records.reduce<Record<string, number>>((acc, item) => { acc[item.department] = (acc[item.department] || 0) + 1; return acc; }, {});
  return { total: records.length, unauthorized, sensitive, riskRecords, approvedCount: records.length - unauthorized.length, appCounts, departmentCounts };
}

export function analyzeSocLogs(logs: SocLog[]): Incident[] {
  const incidents: Incident[] = [];
  const failures = new Map<string, SocLog[]>();
  const portGroups = new Map<string, SocLog[]>();
  for (const log of logs) {
    if (/fail|denied|blocked/i.test(`${log.status} ${log.event_type}`)) {
      const key = `${log.source_ip || 'unknown'}|${log.username || 'unknown'}`;
      failures.set(key, [...(failures.get(key) || []), log]);
    }
    if (/connect|network|port/i.test(log.event_type)) {
      const key = log.source_ip || 'unknown';
      portGroups.set(key, [...(portGroups.get(key) || []), log]);
    }
    if (/privilege|role|admin|permission/i.test(`${log.event_type} ${log.details}`)) {
      incidents.push({ id: `SOC-${incidents.length + 1}`, title: 'Unexpected privilege or role activity', severity: 'High', category: 'Privilege Activity', source: log.source_ip || 'Unknown source', occurrences: 1, reason: log.details || log.event_type, firstSeen: log.timestamp, status: 'Open' });
    }
  }
  for (const [key, rows] of failures) {
    if (rows.length >= 3) {
      const [ip, user] = key.split('|');
      incidents.push({ id: `SOC-${incidents.length + 1}`, title: 'Repeated failed authentication', severity: rows.length >= 5 ? 'High' : 'Medium', category: 'Authentication', source: ip, occurrences: rows.length, reason: `${rows.length} failed or denied events associated with user ${user}.`, firstSeen: rows[0].timestamp, status: 'Open' });
    }
  }
  for (const [ip, rows] of portGroups) {
    const distinctPorts = new Set(rows.map((row) => String(row.destination_port)).filter((port) => port && port !== 'undefined'));
    if (distinctPorts.size >= 5) incidents.push({ id: `SOC-${incidents.length + 1}`, title: 'Possible port enumeration', severity: distinctPorts.size >= 8 ? 'High' : 'Medium', category: 'Network Reconnaissance', source: ip, occurrences: distinctPorts.size, reason: `Source contacted ${distinctPorts.size} distinct destination ports in the supplied log set. Validate time window and asset context.`, firstSeen: rows[0].timestamp, status: 'Open' });
  }
  return incidents.sort((a, b) => ({ Critical: 4, High: 3, Medium: 2, Low: 1 }[b.severity] - { Critical: 4, High: 3, Medium: 2, Low: 1 }[a.severity]));
}

export function riskLabel(score: number): RiskLevel {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

export function riskScore(level: RiskLevel): number {
  return ({ LOW: 15, MEDIUM: 40, HIGH: 70, CRITICAL: 95 })[level];
}
