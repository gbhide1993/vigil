"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VigilAPI = void 0;
const REQUEST_TIMEOUT_MS = 3000;
const HEALTH_CHECK_TIMEOUT_MS = 10000;
class VigilAPI {
    constructor(port) {
        this.port = port;
    }
    baseUrl() {
        return `http://127.0.0.1:${this.port}`;
    }
    async fetchWithTimeout(url, init, timeoutMs = REQUEST_TIMEOUT_MS) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            const response = await fetch(url, { ...init, signal: controller.signal });
            // Consume the body so the underlying socket can be released back to the pool
            let data = null;
            try {
                data = await response.json();
            }
            catch {
                data = null;
            }
            return { ok: response.ok, status: response.status, data };
        }
        finally {
            clearTimeout(timer);
        }
    }
    async mcpCall(tool, params) {
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
        }
        catch {
            return null;
        }
    }
    async getJson(path) {
        try {
            const res = await this.fetchWithTimeout(`${this.baseUrl()}${path}`);
            if (!res.ok) {
                return null;
            }
            return res.data;
        }
        catch {
            return null;
        }
    }
    async isOnline() {
        try {
            const res = await this.fetchWithTimeout(`${this.baseUrl()}/health`, undefined, HEALTH_CHECK_TIMEOUT_MS);
            return res.ok;
        }
        catch {
            return false;
        }
    }
    async getCapabilities() {
        return this.getJson('/capabilities');
    }
    async getCurrentSession() {
        const result = await this.mcpCall('get_current_session', {});
        if (!result) {
            return null;
        }
        return {
            session_id: result.session_id ?? null,
            active: !!result.active,
            agent: result.agent ?? null,
            duration_min: result.duration_min ?? 0,
            files_touched: result.files_touched ?? [],
            red_lines: result.red_lines ?? 0,
            friction_signals: result.friction_signals ?? 0,
            status: result.status ?? 'offline'
        };
    }
    async getRedLineEvents(sinceHours = 24) {
        const result = await this.mcpCall('get_red_line_events', { since_hours: sinceHours });
        if (!result || !Array.isArray(result.events)) {
            return Array.isArray(result) ? result : [];
        }
        return result.events;
    }
    async getFrictionFindings() {
        const result = await this.getJson('/mcp/findings');
        if (!result) {
            return [];
        }
        return Array.isArray(result) ? result : (result.findings ?? []);
    }
    async getEvidenceSummary() {
        return this.getJson('/mcp/summary?days=7');
    }
    async getSessionHistory(n = 5) {
        const result = await this.getJson(`/mcp/sessions?n=${n}`);
        if (!result) {
            return [];
        }
        return Array.isArray(result) ? result : (result.sessions ?? []);
    }
}
exports.VigilAPI = VigilAPI;
//# sourceMappingURL=api.js.map