export function fmtDate(s: string): string {
  try {
    // SQLite stores UTC datetimes without a timezone marker — append Z so JS
    // parses them as UTC instead of local time.
    const utc = /[Z+\-]\d{2}:?\d{2}$/.test(s) ? s : s.replace(' ', 'T') + 'Z';
    return new Date(utc).toLocaleString();
  } catch { return s; }
}

export function fmtUnixTs(ts: number): string {
  try { return new Date(ts * 1000).toLocaleString(); } catch { return String(ts); }
}

export function fmtResults(raw: string | null): string {
  if (!raw) return '';
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}
