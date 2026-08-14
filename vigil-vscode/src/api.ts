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
      // /mcp/call always wraps the tool's return value as { tool, result, error, evidence_note }
      return res.data?.result ?? null;
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
    const url = `${this.baseUrl()}/health`;
    try {
      console.log(
        `[health] attempting ${url} port=${this.port} pid=${process.pid} platform=${process.platform} node=${process.version}`
      );
      const res = await this.fetchWithTimeout(url, undefined, HEALTH_CHECK_TIMEOUT_MS);
      console.log(`[health] response status=${res.status} url=${url} port=${this.port}`);
      console.log(`[health] response ok=${res.ok} url=${url} port=${this.port}`);
      return res.ok;
    } catch (err: any) {
      console.error(
        `[health] exception name=${err?.name ?? 'unknown'} message=${err?.message ?? 'unknown'} url=${url} port=${this.port} pid=${process.pid} platform=${process.platform} node=${process.version}`
      );
      console.error(err?.stack ?? '[health] no stack available');
      return false;
    }
  }

  async getCapabilities(): Promise<any | null> {
    return this.getJson('/capabilities');
  }

  async getCurrentSession(): Promise<SessionStatus | null> {
    const url = `${this.baseUrl()}/mcp/call`;
    const requestBody = { tool: 'get_current_session', params: {} };
    console.log(`[VIGIL DEBUG][getCurrentSession] request url=${url} body=${JSON.stringify(requestBody)}`);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });

      const rawBody = await response.text();
      console.log(`[VIGIL DEBUG][getCurrentSession] raw response status=${response.status} ok=${response.ok} body=${rawBody}`);

      if (!response.ok) {
        console.log('[VIGIL DEBUG][getCurrentSession] parsed result=null');
        return null;
      }

      let body: any = null;
      try {
        body = rawBody ? JSON.parse(rawBody) : null;
      } catch (err: any) {
        console.error(
          `[VIGIL DEBUG][getCurrentSession] failed to parse response body name=${err?.name ?? 'unknown'} message=${err?.message ?? 'unknown'}`
        );
        console.log('[VIGIL DEBUG][getCurrentSession] parsed result=null');
        return null;
      }

      // /mcp/call wraps the tool's return value as { tool, result, error, evidence_note }
      const result = body?.result ?? null;
      console.log(`[VIGIL DEBUG][getCurrentSession] parsed result=${JSON.stringify(result)}`);

      if (!result) {
        return null;
      }

      const session: SessionStatus = {
        session_id: result.session_id ?? null,
        active: result.status === 'active' || result.active === true,
        agent: result.agent ?? null,
        duration_min: result.duration_min ?? 0,
        files_touched: Array.isArray(result.files_touched)
          ? result.files_touched
          : [],
        red_lines: result.red_lines ?? 0,
        friction_signals: result.friction_signals ?? 0,
        status: result.status ?? 'offline'
      };

      console.log(`[VIGIL DEBUG][getCurrentSession] session.active=${session.active}`);
      console.log(`[VIGIL DEBUG][getCurrentSession] session.status=${session.status}`);
      console.log(`[VIGIL DEBUG][getCurrentSession] session.session_id=${session.session_id}`);

      return session;
    } catch (err: any) {
      console.error(
        `[VIGIL DEBUG][getCurrentSession] request failed name=${err?.name ?? 'unknown'} message=${err?.message ?? 'unknown'}`
      );
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async getRedLineEvents(sinceHours = 24): Promise<RedLineEvent[]> {
    const result = await this.mcpCall('get_red_line_events', { since_hours: sinceHours });
    if (!result || !Array.isArray(result.events)) {
      return Array.isArray(result) ? result : [];
    }
    return result.events;
  }

  async getFrictionFindings(): Promise<FrictionFinding[]> {
    const body = await this.getJson('/mcp/findings');
    const result = body?.result;
    return Array.isArray(result) ? result : [];
  }

  async getEvidenceSummary(): Promise<any | null> {
    const body = await this.getJson('/mcp/summary?days=7');
    return body?.result ?? null;
  }

  async getSessionHistory(n = 5): Promise<any[]> {
    const body = await this.getJson(`/mcp/sessions?n=${n}`);
    const result = body?.result;
    return Array.isArray(result) ? result : [];
  }
}
