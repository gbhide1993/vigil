export interface SessionStatus {
  session_id: string | null;
  active: boolean;
  agent: string | null;
  duration_min: number;
  files_touched: string[];
  red_lines: number;
  friction_signals: number;
  status: 'active' | 'idle' | 'complete' | 'offline';
}

export interface RedLineEvent {
  event_id: string;
  type: string;
  severity: string;
  description: string;
  timestamp: string;
  process: string;
  filepath: string;
  session_id: string;
}

export interface FrictionFinding {
  finding_type: string;
  confidence: number;
  filepath: string;
  description: string;
  session_id: string;
}

const REQUEST_TIMEOUT_MS = 3000;
const HEALTH_CHECK_TIMEOUT_MS = 10000;

export class VigilAPI {
  constructor(private port: number) {}

  private baseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  private async fetchWithTimeout(url: string, init?: RequestInit, timeoutMs: number = REQUEST_TIMEOUT_MS): Promise<{ ok: boolean; status: number; data: any }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { ...init, signal: controller.signal });
      // Consume the body so the underlying socket can be released back to the pool
      let data: any = null;
      try {
        data = await response.json();
      } catch {
        data = null;
      }
      return { ok: response.ok, status: response.status, data };
    } finally {
      clearTimeout(timer);
    }
  }

  private async mcpCall(tool: string, params: Record<string, unknown>): Promise<any | null> {
    try {
      const res = await this.fetchWithTimeout(`${this.baseUrl()}/mcp/call`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool, params })
      });
      if (!res.ok) {
        return null;
      }
      return res.data;
    } catch {
      return null;
    }
  }

  private async getJson(path: string): Promise<any | null> {
    try {
      const res = await this.fetchWithTimeout(`${this.baseUrl()}${path}`);
      if (!res.ok) {
        return null;
      }
      return res.data;
    } catch {
      return null;
    }
  }

  async isOnline(): Promise<boolean> {
    try {
      const res = await this.fetchWithTimeout(`${this.baseUrl()}/health`, undefined, HEALTH_CHECK_TIMEOUT_MS);
      return res.ok;
    } catch {
      return false;
    }
  }

  async getCapabilities(): Promise<any | null> {
    return this.getJson('/capabilities');
  }

  async getCurrentSession(): Promise<SessionStatus | null> {
    const result = await this.mcpCall('get_current_session', {});
    if (!result) {
      return null;
    }
    return {
      session_id: result.session_id ?? null,
      active: result.status === 'active' || result.active === true,
      agent: result.agent ?? null,
      duration_min: result.duration_min ?? 0,
      files_touched: result.files_touched ?? [],
      red_lines: result.red_lines ?? 0,
      friction_signals: result.friction_signals ?? 0,
      status: result.status ?? 'offline'
    };
  }

  async getRedLineEvents(sinceHours = 24): Promise<RedLineEvent[]> {
    const result = await this.mcpCall('get_red_line_events', { since_hours: sinceHours });
    if (!result || !Array.isArray(result.events)) {
      return Array.isArray(result) ? result : [];
    }
    return result.events;
  }

  async getFrictionFindings(): Promise<FrictionFinding[]> {
    const result = await this.getJson('/mcp/findings');
    if (!result) {
      return [];
    }
    return Array.isArray(result) ? result : (result.findings ?? []);
  }

  async getEvidenceSummary(): Promise<any | null> {
    return this.getJson('/mcp/summary?days=7');
  }

  async getSessionHistory(n = 5): Promise<any[]> {
    const result = await this.getJson(`/mcp/sessions?n=${n}`);
    if (!result) {
      return [];
    }
    return Array.isArray(result) ? result : (result.sessions ?? []);
  }
}
