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
/** Returns the URL to download a specific export file. */
export const exportDownloadUrl = (filename: string) =>
  `${BASE}/exports/${encodeURIComponent(filename)}`;

export interface ModuleMeta {
  job_type:        string;
  name:            string;
  category:        string;
  description:     string;
  required_config: string[];
  optional_config: string[];
  default_port:    number | null;
  trigger_ports:   number[];
}

export const getModules = () => req<ModuleMeta[]>('/modules');
