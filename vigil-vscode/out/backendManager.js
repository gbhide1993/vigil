"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.BackendManager = void 0;
exports.releaseLock = releaseLock;
const vscode = __importStar(require("vscode"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const child_process_1 = require("child_process");
const HEALTH_CHECK_TIMEOUT_MS = 10000;
const START_WAIT_TIMEOUT_MS = 30000;
const START_WAIT_POLL_MS = 1000;
const ALREADY_RUNNING_EXTRA_WAIT_MS = 30000;
const LOCK_FILE_PATH = path.join(os.tmpdir(), 'vigil-backend.lock');
function isPidRunning(pid) {
    try {
        const output = (0, child_process_1.execSync)(`tasklist /FI "PID eq ${pid}" /NH`, {
            encoding: 'utf8',
            windowsHide: true
        });
        return output.includes(String(pid));
    }
    catch {
        return false;
    }
}
function acquireLock() {
    try {
        if (fs.existsSync(LOCK_FILE_PATH)) {
            const contents = fs.readFileSync(LOCK_FILE_PATH, 'utf8').trim();
            const lockedPid = parseInt(contents, 10);
            if (!isNaN(lockedPid) && isPidRunning(lockedPid)) {
                return false;
            }
        }
        fs.writeFileSync(LOCK_FILE_PATH, String(process.pid), 'utf8');
        return true;
    }
    catch {
        return true;
    }
}
function releaseLock() {
    try {
        if (fs.existsSync(LOCK_FILE_PATH)) {
            fs.unlinkSync(LOCK_FILE_PATH);
        }
    }
    catch {
        // ignore cleanup failure
    }
}
class BackendManager {
    constructor(context, port) {
        this.context = context;
        this.port = port;
        this._state = 'offline';
        this._capabilities = null;
        this._onStateChange = new vscode.EventEmitter();
        this.onStateChange = this._onStateChange.event;
    }
    get state() {
        return this._state;
    }
    get capabilities() {
        return this._capabilities;
    }
    setState(state) {
        this._state = state;
        this._onStateChange.fire(state);
    }
    async checkHealth() {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), HEALTH_CHECK_TIMEOUT_MS);
        const url = `http://127.0.0.1:${this.port}/health`;
        try {
            console.log(`[health] attempting ${url} port=${this.port} pid=${process.pid} platform=${process.platform} node=${process.version}`);
            const res = await fetch(url, { signal: controller.signal });
            console.log(`[health] response status=${res.status} url=${url} port=${this.port}`);
            console.log(`[health] response ok=${res.ok} url=${url} port=${this.port}`);
            return res.ok;
        }
        catch (err) {
            console.error(`[health] exception name=${err?.name ?? 'unknown'} message=${err?.message ?? 'unknown'} url=${url} port=${this.port} pid=${process.pid} platform=${process.platform} node=${process.version}`);
            console.error(err?.stack ?? '[health] no stack available');
            return false;
        }
        finally {
            clearTimeout(timer);
        }
    }
    async waitForHealth(timeoutMs) {
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
            if (await this.checkHealth()) {
                return true;
            }
            await new Promise((resolve) => setTimeout(resolve, START_WAIT_POLL_MS));
        }
        return false;
    }
    isBackendProcessRunning() {
        try {
            const output = (0, child_process_1.execSync)('tasklist /FI "IMAGENAME eq vigil-backend.exe" /NH', {
                encoding: 'utf8',
                windowsHide: true
            });
            return output.includes('vigil-backend.exe');
        }
        catch {
            return false;
        }
    }
    spawnDetached(exePath) {
        const child = (0, child_process_1.spawn)(exePath, [], {
            detached: true,
            stdio: 'ignore'
        });
        child.unref();
    }
    readRegistryInstallPath() {
        try {
            const output = (0, child_process_1.execSync)('reg query "HKCU\\Software\\Vigil" /v InstallPath', {
                encoding: 'utf8',
                windowsHide: true
            });
            const match = output.match(/InstallPath\s+REG_SZ\s+(.+)/);
            if (match) {
                return match[1].trim();
            }
            return null;
        }
        catch {
            return null;
        }
    }
    async tryRegistryInstall() {
        const installPath = this.readRegistryInstallPath();
        if (!installPath) {
            return false;
        }
        const exePath = path.join(installPath, 'Vigil.exe');
        if (!fs.existsSync(exePath)) {
            return false;
        }
        this.setState('starting');
        this.spawnDetached(exePath);
        return this.waitForHealth(START_WAIT_TIMEOUT_MS);
    }
    async tryFallbackPath() {
        const localAppData = process.env.LOCALAPPDATA;
        if (!localAppData) {
            return false;
        }
        const exePath = path.join(localAppData, 'Programs', 'Vigil', 'Vigil.exe');
        if (!fs.existsSync(exePath)) {
            return false;
        }
        this.setState('starting');
        this.spawnDetached(exePath);
        return this.waitForHealth(START_WAIT_TIMEOUT_MS);
    }
    sha256File(filePath) {
        const buffer = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(buffer).digest('hex');
    }
    async downloadAndVerify() {
        const manifestUrl = 'https://download.getvvault.com/manifest.json';
        let manifest;
        try {
            const res = await fetch(manifestUrl);
            if (!res.ok) {
                return null;
            }
            manifest = await res.json();
        }
        catch {
            return null;
        }
        const assetInfo = manifest['win_x64'];
        if (!assetInfo || !assetInfo.url || !assetInfo.sha256) {
            return null;
        }
        const storageDir = this.context.globalStorageUri.fsPath;
        if (!fs.existsSync(storageDir)) {
            fs.mkdirSync(storageDir, { recursive: true });
        }
        const destPath = path.join(storageDir, 'Vigil.exe');
        const downloaded = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Vigil: downloading backend (one-time setup)',
            cancellable: false
        }, async () => {
            try {
                const res = await fetch(assetInfo.url);
                if (!res.ok || !res.body) {
                    return false;
                }
                const arrayBuffer = await res.arrayBuffer();
                fs.writeFileSync(destPath, Buffer.from(arrayBuffer));
                return true;
            }
            catch {
                return false;
            }
        });
        if (!downloaded) {
            return null;
        }
        const actualHash = this.sha256File(destPath);
        if (actualHash.toLowerCase() !== String(assetInfo.sha256).toLowerCase()) {
            try {
                fs.unlinkSync(destPath);
            }
            catch {
                // ignore cleanup failure
            }
            throw new Error('Vigil backend download failed checksum verification.');
        }
        return destPath;
    }
    async tryDownloadInstall() {
        this.setState('downloading');
        let exePath;
        try {
            exePath = await this.downloadAndVerify();
        }
        catch (err) {
            vscode.window.showErrorMessage(`Vigil: backend download failed verification (${err.message}). Please install Vigil manually.`);
            return false;
        }
        if (!exePath) {
            vscode.window.showInformationMessage('Vigil backend not found. Install from download.getvvault.com', 'Download').then(selection => {
                if (selection === 'Download') {
                    vscode.env.openExternal(vscode.Uri.parse('https://download.getvvault.com/Vigil-Setup.exe'));
                }
            });
            return false;
        }
        this.setState('starting');
        this.spawnDetached(exePath);
        return this.waitForHealth(START_WAIT_TIMEOUT_MS);
    }
    async ensureVigilRunning() {
        console.log('[VIGIL TRACE][ensureVigilRunning] before checkHealth()');
        const healthOk = await this.checkHealth();
        console.log(`[VIGIL TRACE][ensureVigilRunning] after checkHealth() result=${healthOk}`);
        if (healthOk) {
            this.setState('running');
            console.log('[VIGIL TRACE][ensureVigilRunning] before loadCapabilities()');
            await this.loadCapabilities();
            console.log('[VIGIL TRACE][ensureVigilRunning] after loadCapabilities()');
            console.log('[VIGIL TRACE][ensureVigilRunning] returning true');
            return true;
        }
        if (this.isBackendProcessRunning() || !acquireLock()) {
            console.log('Vigil backend already running, waiting...');
            if (await this.waitForHealth(START_WAIT_TIMEOUT_MS + ALREADY_RUNNING_EXTRA_WAIT_MS)) {
                this.setState('running');
                console.log('[VIGIL TRACE][ensureVigilRunning] before loadCapabilities()');
                await this.loadCapabilities();
                console.log('[VIGIL TRACE][ensureVigilRunning] after loadCapabilities()');
                console.log('[VIGIL TRACE][ensureVigilRunning] returning true');
                return true;
            }
            this.setState('offline');
            console.log('[VIGIL TRACE][ensureVigilRunning] returning false');
            return false;
        }
        if (await this.tryRegistryInstall()) {
            this.setState('running');
            console.log('[VIGIL TRACE][ensureVigilRunning] before loadCapabilities()');
            await this.loadCapabilities();
            console.log('[VIGIL TRACE][ensureVigilRunning] after loadCapabilities()');
            console.log('[VIGIL TRACE][ensureVigilRunning] returning true');
            return true;
        }
        if (await this.tryFallbackPath()) {
            this.setState('running');
            console.log('[VIGIL TRACE][ensureVigilRunning] before loadCapabilities()');
            await this.loadCapabilities();
            console.log('[VIGIL TRACE][ensureVigilRunning] after loadCapabilities()');
            console.log('[VIGIL TRACE][ensureVigilRunning] returning true');
            return true;
        }
        if (await this.tryDownloadInstall()) {
            this.setState('running');
            console.log('[VIGIL TRACE][ensureVigilRunning] before loadCapabilities()');
            await this.loadCapabilities();
            console.log('[VIGIL TRACE][ensureVigilRunning] after loadCapabilities()');
            console.log('[VIGIL TRACE][ensureVigilRunning] returning true');
            return true;
        }
        this.setState('offline');
        console.log('[VIGIL TRACE][ensureVigilRunning] returning false');
        return false;
    }
    async loadCapabilities() {
        try {
            const res = await fetch(`http://127.0.0.1:${this.port}/capabilities`);
            if (res.ok) {
                this._capabilities = await res.json();
            }
        }
        catch {
            this._capabilities = null;
        }
    }
    hasCapability(name) {
        if (!this._capabilities) {
            return true;
        }
        if (Array.isArray(this._capabilities)) {
            return this._capabilities.includes(name);
        }
        return !!this._capabilities[name];
    }
}
exports.BackendManager = BackendManager;
//# sourceMappingURL=backendManager.js.map