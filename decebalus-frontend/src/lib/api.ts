const BASE = '/api';

export interface Port {
  number: number;
  protocol: string;
  status: string;
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
  const r = await fetch(`${BASE}${path}`, init);
  if (!r.ok) {
    const body = await r.json().catch(() => ({ error: r.statusText }));
    throw new Error(body.error ?? r.statusText);
  }
  return r.json();
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
