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
exports.BackendManager = exports.DOWNLOAD_ONLY_COMMAND = exports.INSTALL_BACKEND_COMMAND = void 0;
exports.releaseLock = releaseLock;
const vscode = __importStar(require("vscode"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const child_process_1 = require("child_process");
const HEALTH_CHECK_TIMEOUT_MS = 10000;
const START_WAIT_TIMEOUT_MS = 60000;
const START_WAIT_POLL_MS = 1000;
const ALREADY_RUNNING_EXTRA_WAIT_MS = 30000;
const INSTALL_TIMEOUT_MS = 300000;
const LOCK_FILE_PATH = path.join(os.tmpdir(), 'vigil-backend.lock');
// Where the backend installer comes from. Only this host is trusted: the manifest is read from it, and a
// manifest that points anywhere else is refused.
const DOWNLOAD_HOST = 'download.getvvault.com';
const MANIFEST_URL = `https://${DOWNLOAD_HOST}/manifest.json`;
const STANDALONE_INSTALLER_URL = `https://${DOWNLOAD_HOST}/Vigil-Setup.exe`;
const README_INSTALL_URL = 'https://github.com/gbhide1993/vigil/blob/main/vigil-vscode/README.md#if-vigil-is-not-installed-yet';
// Remembered when the user cancels the install prompt, so it is not shown again on every startup.
const INSTALL_DECLINED_KEY = 'vigil.installPromptDeclined';
exports.INSTALL_BACKEND_COMMAND = 'vigil.installBackend';
exports.DOWNLOAD_ONLY_COMMAND = 'vigil.downloadInstallerOnly';
const BACKEND_MISSING_CONTEXT = 'vigil.backendMissing';
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
        this._missing = false;
        // True once this extension has started Vigil itself, so a slow start is never mistaken for a missing install.
        this.spawnedThisRun = false;
        this._capabilities = null;
        this._onStateChange = new vscode.EventEmitter();
        this.onStateChange = this._onStateChange.event;
        // "Vigil: Install Backend": runs the install flow on request, even after the prompt was cancelled.
        context.subscriptions.push(vscode.commands.registerCommand(exports.INSTALL_BACKEND_COMMAND, async () => {
            await this.context.globalState.update(INSTALL_DECLINED_KEY, false);
            if (await this.tryDownloadInstall(true)) {
                this.setState('running');
                await this.loadCapabilities();
            }
            else {
                this.setState('offline');
            }
        }), vscode.commands.registerCommand(exports.DOWNLOAD_ONLY_COMMAND, async () => {
            await this.downloadInstallerOnlyFlow();
        }));
    }
    /** True when no installed backend was found. The sidebar shows an install panel instead of a prompt. */
    get backendMissing() {
        return this._missing;
    }
    setMissing(missing) {
        if (this._missing === missing) {
            return;
        }
        this._missing = missing;
        void vscode.commands.executeCommand('setContext', BACKEND_MISSING_CONTEXT, missing);
    }
    get state() {
        return this._state;
    }
    get capabilities() {
        return this._capabilities;
    }
    setState(state) {
        if (state === 'running') {
            this.setMissing(false);
        }
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
    spawnDetached(exePath) {
        this.spawnedThisRun = true;
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
    /** Reads the download manifest. Returns the win_x64 asset, or a message that says why there is none. */
    async readManifest() {
        let manifest;
        try {
            const res = await fetch(MANIFEST_URL);
            if (!res.ok) {
                return { problem: `the download manifest could not be read (HTTP ${res.status})` };
            }
            manifest = await res.json();
        }
        catch {
            return { problem: 'the download manifest could not be reached' };
        }
        const asset = manifest && manifest['win_x64'];
        if (!asset || !asset.url || !asset.sha256) {
            return { problem: 'the download manifest has no Windows (win_x64) installer entry' };
        }
        return { asset: { url: String(asset.url), sha256: String(asset.sha256) } };
    }
    /** Null when the url is on the trusted host over https, otherwise the reason it is refused. */
    untrustedHostProblem(url) {
        let parsed;
        try {
            parsed = new URL(url);
        }
        catch {
            return `the installer address in the manifest is not a valid URL (${url})`;
        }
        if (parsed.protocol !== 'https:' || parsed.host.toLowerCase() !== DOWNLOAD_HOST) {
            return `the manifest points to ${parsed.protocol}//${parsed.host}, which is not ${DOWNLOAD_HOST}`;
        }
        return null;
    }
    offerStandaloneInstaller(problem) {
        vscode.window.showWarningMessage(`Vigil: could not fetch the backend installer automatically (${problem}). ` +
            `You can download the installer yourself from ${STANDALONE_INSTALLER_URL} and check its SHA256 against the one published with the release.`, 'Open download page').then(selection => {
            if (selection === 'Open download page') {
                vscode.env.openExternal(vscode.Uri.parse(STANDALONE_INSTALLER_URL));
            }
        });
    }
    /** Downloads the installer to destPath and checks it against the expected SHA256. Returns the verified
     * hash, or null when the download itself failed. Throws on a hash mismatch (the file is deleted). */
    async downloadToAndVerify(asset, destPath) {
        const downloaded = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Vigil: downloading backend installer (about 110 MB)',
            cancellable: false
        }, async () => {
            try {
                const res = await fetch(asset.url);
                if (!res.ok || !res.body) {
                    return false;
                }
                const arrayBuffer = await res.arrayBuffer();
                fs.mkdirSync(path.dirname(destPath), { recursive: true });
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
        if (actualHash.toLowerCase() !== asset.sha256.toLowerCase()) {
            try {
                fs.unlinkSync(destPath);
            }
            catch {
                // ignore cleanup failure
            }
            throw new Error('Vigil backend download failed checksum verification.');
        }
        return actualHash;
    }
    /** Asks before anything is downloaded. Returns the choice, or undefined when the user cancelled. */
    async askInstallConsent(asset) {
        const choice = await vscode.window.showInformationMessage('Vigil needs its local backend. Download and install it now?', {
            modal: true,
            detail: `Download: about 110 MB from ${DOWNLOAD_HOST} (Vigil-Setup.exe).\n\n` +
                'The installer is not code-signed, and it needs administrator approval to install.\n\n' +
                `It will be checked against this SHA256 before it is used:\n${asset.sha256}\n` +
                'That value comes from the same server as the installer. For a separate check, download the installer yourself and compare it with the hash published with the release.\n\n' +
                `"Download only" saves the installer to your Downloads folder and does not run it.\n\n` +
                `Install steps and the unsigned-installer note: ${README_INSTALL_URL}`
        }, 'Install now', 'Download only');
        if (choice === 'Install now') {
            return 'install';
        }
        if (choice === 'Download only') {
            return 'download';
        }
        return undefined;
    }
    /** The consent-first install flow. `manual` is true when the user ran "Vigil: Install Backend". */
    async tryDownloadInstall(manual = false) {
        // A cancelled prompt is remembered: no prompt and no network call on later startups.
        if (!manual && this.context.globalState.get(INSTALL_DECLINED_KEY)) {
            return false;
        }
        const manifest = await this.readManifest();
        if ('problem' in manifest) {
            this.offerStandaloneInstaller(manifest.problem);
            return false;
        }
        const asset = manifest.asset;
        const hostProblem = this.untrustedHostProblem(asset.url);
        if (hostProblem) {
            vscode.window.showErrorMessage(`Vigil: refusing to download the backend installer: ${hostProblem}. Only ${DOWNLOAD_HOST} is allowed. ` +
                `Download Vigil from ${STANDALONE_INSTALLER_URL} instead.`);
            return false;
        }
        const consent = await this.askInstallConsent(asset);
        if (consent === undefined) {
            await this.context.globalState.update(INSTALL_DECLINED_KEY, true);
            vscode.window.showInformationMessage('Vigil: backend install skipped. Run "Vigil: Install Backend" from the Command Palette to install it later.');
            return false;
        }
        if (consent === 'download') {
            return this.downloadOnly(asset);
        }
        this.setState('downloading');
        let verifiedHash;
        const installerPath = path.join(this.context.globalStorageUri.fsPath, 'Vigil-Setup.exe');
        try {
            verifiedHash = await this.downloadToAndVerify(asset, installerPath);
        }
        catch (err) {
            vscode.window.showErrorMessage(`Vigil: backend download failed verification (${err.message}). Please install Vigil manually.`);
            return false;
        }
        if (verifiedHash === null) {
            this.offerStandaloneInstaller('the installer download failed');
            return false;
        }
        // Run the installer silently, wait for it to finish, then start the backend.
        vscode.window.showInformationMessage(`Vigil: installer verified (SHA256 ${verifiedHash}). Installing the backend, please wait...`);
        const exitCode = await this.runInstaller(installerPath);
        if (exitCode !== 0) {
            const why = exitCode === null ? 'it could not be started or did not finish in 5 minutes' : `exit code ${exitCode}`;
            vscode.window.showErrorMessage(`Vigil: the installer did not finish successfully (${why}). You can run it yourself from ${installerPath}.`);
            this.setState('offline');
            return false;
        }
        // After silent install, try registry and fallback paths to find and start the exe
        this.setState('starting');
        this.spawnedThisRun = false;
        if (await this.tryRegistryInstall()) {
            return true;
        }
        if (!this.spawnedThisRun && (await this.tryFallbackPath())) {
            return true;
        }
        if (this.spawnedThisRun) {
            vscode.window.showWarningMessage('Vigil is installed and was started, but it is taking longer than usual to respond. Give it a minute, then run "Vigil: Refresh".');
            this.setState('offline');
            return false;
        }
        // If still not found, ask user to restart VS Code
        vscode.window.showInformationMessage('Vigil installed. Please restart VS Code to complete setup.', 'Restart').then(selection => {
            if (selection === 'Restart') {
                vscode.commands.executeCommand('workbench.action.reloadWindow');
            }
        });
        return false;
    }
    /** Runs the installer without blocking the extension host. Resolves with the exit code, or null when it
     * could not be started or did not exit within INSTALL_TIMEOUT_MS. */
    runInstaller(installerPath) {
        return new Promise((resolve) => {
            let settled = false;
            let timer;
            const done = (code) => {
                if (settled) {
                    return;
                }
                settled = true;
                if (timer) {
                    clearTimeout(timer);
                }
                resolve(code);
            };
            timer = setTimeout(() => {
                console.error('[vigil] installer did not exit within the time limit');
                done(null);
            }, INSTALL_TIMEOUT_MS);
            try {
                // /SILENT runs without UI, /NORESTART suppresses reboot prompt
                const child = (0, child_process_1.spawn)(installerPath, ['/SILENT', '/NORESTART'], { windowsHide: true, stdio: 'ignore' });
                child.on('error', (err) => {
                    console.error(`[vigil] installer failed: ${err.message}`);
                    done(null);
                });
                child.on('exit', (code) => done(code));
            }
            catch (err) {
                console.error(`[vigil] installer failed: ${err?.message ?? 'unknown'}`);
                done(null);
            }
        });
    }
    /** "Download installer only" from the sidebar: no install, no run. */
    async downloadInstallerOnlyFlow() {
        const manifest = await this.readManifest();
        if ('problem' in manifest) {
            this.offerStandaloneInstaller(manifest.problem);
            return;
        }
        const hostProblem = this.untrustedHostProblem(manifest.asset.url);
        if (hostProblem) {
            vscode.window.showErrorMessage(`Vigil: refusing to download the installer: ${hostProblem}. Only ${DOWNLOAD_HOST} is allowed. ` +
                `Download Vigil from ${STANDALONE_INSTALLER_URL} instead.`);
            return;
        }
        await this.downloadOnly(manifest.asset);
    }
    /** "Download only": saves the verified installer to the Downloads folder and does not run it. */
    async downloadOnly(asset) {
        const destPath = path.join(os.homedir(), 'Downloads', 'Vigil-Setup.exe');
        let verifiedHash;
        try {
            verifiedHash = await this.downloadToAndVerify(asset, destPath);
        }
        catch (err) {
            vscode.window.showErrorMessage(`Vigil: the download failed verification (${err.message}). Nothing was saved.`);
            return false;
        }
        if (verifiedHash === null) {
            this.offerStandaloneInstaller('the installer download failed');
            return false;
        }
        vscode.window.showInformationMessage(`Vigil: installer saved to ${destPath} (SHA256 verified: ${verifiedHash}). It was not run. ` +
            'Run it yourself when you are ready, then restart VS Code.', 'Show in folder').then(selection => {
            if (selection === 'Show in folder') {
                vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(destPath));
            }
        });
        // Nothing was installed, so the backend is still not running.
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
            // Still not healthy. The extension does not stop the recorder: it may be mid-write.
            console.log('[vigil] backend process found but not healthy after wait; leaving it running');
            this.setState('offline');
            vscode.window.showWarningMessage('Vigil: the backend process is running but not answering. Restart Vigil from the system tray, ' +
                'or end vigil-backend.exe in Task Manager. The extension will not stop it for you.');
            return false;
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
        this.spawnedThisRun = false;
        if (await this.tryRegistryInstall()) {
            this.setState('running');
            await this.loadCapabilities();
            return true;
        }
        if (!this.spawnedThisRun && (await this.tryFallbackPath())) {
            this.setState('running');
            await this.loadCapabilities();
            return true;
        }
        if (this.spawnedThisRun) {
            // Vigil was found and started but did not answer in time. That is not a missing install.
            this.setState('offline');
            vscode.window.showWarningMessage('Vigil was started but is taking longer than usual to respond. It should appear in the sidebar shortly; run "Vigil: Refresh" if it does not.');
            return false;
        }
        // Nothing found. Do not download or prompt at startup: the Vigil sidebar shows an install panel, and
        // the install flow (with its consent dialog) runs only when the user chooses it.
        this.setMissing(true);
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