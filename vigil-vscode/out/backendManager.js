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
            return res.ok;
        }
        catch (err) {
            console.error(`[health] exception name=${err?.name ?? 'unknown'} message=${err?.message ?? 'unknown'} url=${url} port=${this.port}`);
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
    // FIX: Kill zombie vigil-backend processes that are running but not healthy
    killZombieBackends() {
        try {
            (0, child_process_1.execSync)('taskkill /F /IM vigil-backend.exe', {
                encoding: 'utf8',
                windowsHide: true
            });
            console.log('[vigil] killed zombie vigil-backend.exe processes');
        }
        catch {
            // no processes to kill, ignore
        }
    }
    spawnDetached(exePath) {
        const child = (0, child_process_1.spawn)(exePath, [], {
            detached: true,
            stdio: 'ignore'
        });
        child.unref();
    }
    // FIX: Read from the correct registry location (Run key, not a custom key)
    readRegistryInstallPath() {
        // First try the dedicated install path key (if we ever write one)
        try {
            const output = (0, child_process_1.execSync)('reg query "HKCU\\Software\\Vigil" /v InstallPath', {
                encoding: 'utf8',
                windowsHide: true
            });
            const match = output.match(/InstallPath\s+REG_SZ\s+(.+)/);
            if (match) {
                return match[1].trim();
            }
        }
        catch {
            // not found, try fallback
        }
        // FIX: Also check the Run key where Electron registers the auto-launch path
        try {
            const output = (0, child_process_1.execSync)('reg query "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "electron.app.Vigil"', {
                encoding: 'utf8',
                windowsHide: true
            });
            const match = output.match(/electron\.app\.Vigil\s+REG_SZ\s+(.+)/);
            if (match) {
                // Run key value is the full exe path, not the install dir
                const exePath = match[1].trim().replace(/"/g, '');
                return path.dirname(exePath); // return the directory
            }
        }
        catch {
            // not found
        }
        return null;
    }
    async tryRegistryInstall() {
        const installPath = this.readRegistryInstallPath();
        if (!installPath) {
            return false;
        }
        // Try Vigil.exe directly in the path
        const exePath = path.join(installPath, 'Vigil.exe');
        if (fs.existsSync(exePath)) {
            console.log(`[vigil] found via registry: ${exePath}`);
            this.setState('starting');
            this.spawnDetached(exePath);
            return this.waitForHealth(START_WAIT_TIMEOUT_MS);
        }
        // FIX: The Run key gives us the tray dir — backend may be one level up or in parent
        const parentPath = path.dirname(installPath);
        const parentExe = path.join(parentPath, 'Vigil.exe');
        if (fs.existsSync(parentExe)) {
            console.log(`[vigil] found via registry parent: ${parentExe}`);
            this.setState('starting');
            this.spawnDetached(parentExe);
            return this.waitForHealth(START_WAIT_TIMEOUT_MS);
        }
        console.log(`[vigil] registry points to ${installPath} but no Vigil.exe found — stale key`);
        return false;
    }
    async tryFallbackPath() {
        const localAppData = process.env.LOCALAPPDATA;
        const programFiles = process.env.PROGRAMFILES ?? 'C:\\Program Files';
        const candidates = [
            localAppData ? path.join(localAppData, 'Programs', 'Vigil', 'Vigil.exe') : null,
            path.join(programFiles, 'Vigil', 'Vigil.exe'),
            path.join(programFiles, 'Vigil', 'tray', 'Vigil.exe'),
        ].filter(Boolean);
        for (const exePath of candidates) {
            if (fs.existsSync(exePath)) {
                console.log(`[vigil] found via fallback path: ${exePath}`);
                this.setState('starting');
                this.spawnDetached(exePath);
                return this.waitForHealth(START_WAIT_TIMEOUT_MS);
            }
        }
        return false;
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
        // FIX: Keep the correct name — this is the installer, not the backend exe
        const destPath = path.join(storageDir, 'Vigil-Setup.exe');
        const downloaded = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Vigil: downloading backend installer (one-time setup ~110MB)',
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
        let installerPath;
        try {
            installerPath = await this.downloadAndVerify();
        }
        catch (err) {
            vscode.window.showErrorMessage(`Vigil: backend download failed verification (${err.message}). Please install Vigil manually.`);
            return false;
        }
        if (!installerPath) {
            vscode.window.showInformationMessage('Vigil backend not found. Install from download.getvvault.com', 'Download').then(selection => {
                if (selection === 'Download') {
                    vscode.env.openExternal(vscode.Uri.parse('https://download.getvvault.com/Vigil-Setup.exe'));
                }
            });
            return false;
        }
        // FIX: Run the installer silently, then wait for it to finish, then start the backend
        vscode.window.showInformationMessage('Vigil: installing backend, please wait...');
        try {
            // /SILENT runs without UI, /NORESTART suppresses reboot prompt
            (0, child_process_1.spawnSync)(installerPath, ['/SILENT', '/NORESTART'], {
                windowsHide: true,
                timeout: 120000 // 2 minute timeout for install
            });
        }
        catch (err) {
            console.error(`[vigil] installer failed: ${err.message}`);
            return false;
        }
        // After silent install, try registry and fallback paths to find and start the exe
        this.setState('starting');
        if (await this.tryRegistryInstall()) {
            return true;
        }
        if (await this.tryFallbackPath()) {
            return true;
        }
        // If still not found, ask user to restart VS Code
        vscode.window.showInformationMessage('Vigil installed. Please restart VS Code to complete setup.', 'Restart').then(selection => {
            if (selection === 'Restart') {
                vscode.commands.executeCommand('workbench.action.reloadWindow');
            }
        });
        return false;
    }
    async ensureVigilRunning() {
        console.log('[VIGIL TRACE][ensureVigilRunning] before checkHealth()');
        const healthOk = await this.checkHealth();
        console.log(`[VIGIL TRACE][ensureVigilRunning] after checkHealth() result=${healthOk}`);
        if (healthOk) {
            this.setState('running');
            await this.loadCapabilities();
            return true;
        }
        // FIX: If backend process is running but not healthy, it's a zombie — kill it
        // and fall through to the install/download path instead of waiting forever
        if (this.isBackendProcessRunning()) {
            console.log('[vigil] backend process found but not healthy — waiting briefly...');
            if (await this.waitForHealth(START_WAIT_TIMEOUT_MS)) {
                this.setState('running');
                await this.loadCapabilities();
                return true;
            }
            // Still not healthy after 30s — treat as zombie and kill
            console.log('[vigil] backend still not healthy after wait — killing zombie processes');
            this.killZombieBackends();
            // Small delay to let OS release the port
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
        if (!acquireLock()) {
            console.log('[vigil] another VS Code window is starting the backend, waiting...');
            if (await this.waitForHealth(START_WAIT_TIMEOUT_MS + ALREADY_RUNNING_EXTRA_WAIT_MS)) {
                this.setState('running');
                await this.loadCapabilities();
                return true;
            }
            this.setState('offline');
            return false;
        }
        if (await this.tryRegistryInstall()) {
            this.setState('running');
            await this.loadCapabilities();
            return true;
        }
        if (await this.tryFallbackPath()) {
            this.setState('running');
            await this.loadCapabilities();
            return true;
        }
        if (await this.tryDownloadInstall()) {
            this.setState('running');
            await this.loadCapabilities();
            return true;
        }
        this.setState('offline');
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