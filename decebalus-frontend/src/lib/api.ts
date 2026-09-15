const BASE = '/api';

export interface Port {
  number: number;
  protocol: string;
  status: string;
  service: string | null;
  version: string | null;
  cpe: string | null;
}

export interface Vulnerability {
  id: string;
  severity: string;
  description: string;
  /** Enriched NVD detail, merged in by the backend. Null until enrichment runs. */
  detail?: CveDetail | null;
}

export interface Host {
  ip: string;
  hostname: string | null;
  mac_address: string | null;
  os: string | null;
  device_type: string | null;
  status: string;
  last_seen: string;
  first_seen: string;
  ports: Port[];
  banners: string[];
  vulnerabilities: Vulnerability[];
}

export interface Job {
  id: string;
  job_type: string;
  status: string;
  config: { target?: string; [key: string]: any };
  results: string | null;
  created_at: string;
  scheduled_at: number | null;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20_000);
  try {
    const r = await fetch(`${BASE}${path}`, { ...init, signal: controller.signal });
    if (!r.ok) {
      const body = await r.json().catch(() => ({ error: r.statusText }));
      throw new Error(body.error ?? r.statusText);
    }
    return r.json();
  } catch (e: any) {
    if (e.name === 'AbortError') throw new Error('Request timed out');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

export interface Log {
  id: string;
  created_at: string;
  severity: string;
  service: string;
  module: string | null;
  job_id: string | null;
  content: string;
}

export const getLogs       = ()              => req<Log[]>('/logs');
export const getLogsByJob  = (jobId: string) => req<Log[]>(`/logs/${encodeURIComponent(jobId)}`);

export const getJobs  = ()           => req<Job[]>('/jobs');
export const getJob   = (id: string) => req<Job>(`/jobs/${id}`);
export const getHosts = ()           => req<Host[]>('/hosts');
export const getHost  = (ip: string) => req<Host>(`/hosts/${encodeURIComponent(ip)}`);
export const getConfig = ()          => req<{ settings: Record<string, any> }>('/config');

export function createJob(job_type: string, target?: string): Promise<Job> {
  const body: Record<string, any> = { job_type };
  if (target !== undefined) body.target = target;
  return req<Job>('/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export const cancelJob = (id: string) =>
  req<{ message: string }>(`/jobs/${id}/cancel`, { method: 'POST' });

export function createAttackJob(job_type: string, config: Record<string, unknown>): Promise<Job> {
  return req<Job>('/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ job_type, config }),
  });
}

export function scheduleJob(job_type: string, target: string | undefined, scheduledAt: number): Promise<Job> {
  const body: Record<string, any> = { job_type, scheduled_at: scheduledAt };
  if (target !== undefined) body.target = target;
  return req<Job>('/jobs/schedule', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export const saveConfig = (settings: Record<string, any>) =>
  req<void>('/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ settings }),
  });

export interface CveDetail {
  cve_id:           string;
  description:      string;
  cvss_v3_score:    number | null;
  cvss_v3_severity: string | null;
  cvss_v2_score:    number | null;
  cvss_v2_severity: string | null;
  published_at:     string | null;
  references:       string[];
  fetched_at:       string;
}

export const listCves   = ()              => req<CveDetail[]>('/cve');
export const getCve     = (id: string)    => req<CveDetail>(`/cve/${encodeURIComponent(id)}`);
export const syncCves   = ()              => req<Job>('/cve/sync', { method: 'POST' });

export interface ExportFile {
  filename: string;
  size: number;
  modified_at: number | null;
}

export const getExports   = () => req<ExportFile[]>('/exports');
export const triggerExport = () => createJob('export');
export const triggerReport = () => createJob('report');
/** Returns the URL to download a specific export file. */
export const exportDownloadUrl = (filename: string) =>
  `${BASE}/exports/${encodeURIComponent(filename)}`;

export interface ToolReq {
  name:    string;
  binary:  string;
  version: string;
  install: string;
}

export interface ModuleMeta {
  job_type:        string;
  name:            string;
  category:        string;
  description:     string;
  required_config: string[];
  optional_config: string[];
  default_port:    number | null;
  trigger_ports:   number[];
  safety?:         string;
  opsec_noise?:    string;
  produces_facts?: string[];
  requires_cred?:  boolean;
  trigger_facts?:  string[];
  // Extended documentation (from the backend docs layer) for the detail view.
  how_it_works?:    string;
  why_it_works?:    string;
  example_command?: string;
  requires_tools?:  ToolReq[];
  references?:      string[];
}

export const getModules = () => req<ModuleMeta[]>('/modules');

// ── Assumed-breach: engagements, credentials, findings (the war table) ──────

export interface Engagement {
  id:          string;
  name:        string;
  scope_cidrs: string[];
  domain:      string | null;
  dc_ip:       string | null;
  status:      string;
  created_at:  string;
}

export interface Credential {
  id:            string;
  engagement_id: string;
  domain:        string;
  username:      string;
  secret_type:   string;
  secret:        string;
  source_job_id: string | null;
  validated:     boolean;
  valid_on:      string[];
  privilege:     string;
  created_at:    string;
}

export interface Finding {
  id:                string;
  engagement_id:     string;
  dedup_key:         string;
  title:             string;
  category:          string;
  value_score:       number;
  severity:          string;
  rationale:         string;
  suggested_command: string | null;
  auto_runnable:     boolean;
  job_type:          string | null;
  job_config:        Record<string, any>;
  status:            string;
  evidence:          Record<string, any>;
  created_at:        string;
}

export const getFindings    = ()           => req<Finding[]>('/findings');
export const runFinding     = (id: string) => req<Job>(`/findings/${id}/run`, { method: 'POST' });
export const dismissFinding = (id: string) => req<{ message: string }>(`/findings/${id}/dismiss`, { method: 'POST' });
export const runEngine      = ()           => req<{ findings: number }>('/engine/run', { method: 'POST' });

export const getEngagements      = ()           => req<Engagement[]>('/engagements');
export const getActiveEngagement = ()           => req<Engagement | null>('/engagements/active');
export const activateEngagement  = (id: string) => req<{ message: string }>(`/engagements/${id}/activate`, { method: 'POST' });
export const getCredentials      = ()           => req<Credential[]>('/credentials');

export interface CreateEngagementBody {
  name:         string;
  scope_cidrs?: string[];
  domain?:      string;
  dc_ip?:       string;
  username?:    string;
  password?:    string;
}

export const createEngagement = (body: CreateEngagementBody) =>
  req<Engagement>('/engagements', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

export interface HostEvent {
  id:         number;
  created_at: string;
  host_ip:    string;
  event_type: string;
  detail:     string | null;
  severity:   string | null;
}

export const getHistory = (limit = 100) => req<HostEvent[]>(`/history?limit=${limit}`);

// ── Wordlists: bundled SecLists (shipped, offline) + user-saved custom lists ────

export interface WordlistMeta {
  id:           string;
  name:         string;
  category:     string; // 'username' | 'password' | 'discovery'
  source:       string; // 'bundled' | 'custom'
  file_path:    string;
  entry_count:  number;
  size_bytes:   number;
  created_at:   string;
}

export interface WordlistContent {
  id:          string;
  name:        string;
  category:    string;
  entry_count: number;
  content:     string;
}

export const getWordlists = () => req<WordlistMeta[]>('/wordlists');

/** Fetch a list's raw text so it can be loaded into an editable textarea.
 *  Rejects (HTTP 413) for lists too large to edit in the browser. */
export const getWordlistContent = (id: string) =>
  req<WordlistContent>(`/wordlists/${encodeURIComponent(id)}/content`);

export const saveCustomWordlist = (name: string, category: string, content: string) =>
  req<WordlistMeta>('/wordlists/custom', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, category, content }),
  });

export const deleteWordlist = (id: string) =>
  req<{ message: string }>(`/wordlists/${encodeURIComponent(id)}`, { method: 'DELETE' });
