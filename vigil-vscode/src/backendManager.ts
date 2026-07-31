import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync, spawn } from 'child_process';

const HEALTH_CHECK_TIMEOUT_MS = 10000;
const START_WAIT_TIMEOUT_MS = 30000;
const START_WAIT_POLL_MS = 1000;

export type BackendState = 'downloading' | 'starting' | 'running' | 'offline';

export class BackendManager {
  private _state: BackendState = 'offline';
  private _capabilities: any | null = null;
  private _onStateChange = new vscode.EventEmitter<BackendState>();
  readonly onStateChange = this._onStateChange.event;

  constructor(private context: vscode.ExtensionContext, private port: number) {}

  get state(): BackendState {
    return this._state;
  }

  get capabilities(): any | null {
    return this._capabilities;
  }

  private setState(state: BackendState) {
    this._state = state;
    this._onStateChange.fire(state);
  }

  private async checkHealth(): Promise<boolean> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), HEALTH_CHECK_TIMEOUT_MS);
    try {
      const res = await fetch(`http://127.0.0.1:${this.port}/health`, { signal: controller.signal });
      return res.ok;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  private async waitForHealth(timeoutMs: number): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (await this.checkHealth()) {
        return true;
      }
      await new Promise((resolve) => setTimeout(resolve, START_WAIT_POLL_MS));
    }
    return false;
  }

  private spawnDetached(exePath: string) {
    const child = spawn(exePath, [], {
      detached: true,
      stdio: 'ignore'
    });
    child.unref();
  }

  private readRegistryInstallPath(): string | null {
    try {
      const output = execSync('reg query "HKCU\\Software\\Vigil" /v InstallPath', {
        encoding: 'utf8',
        windowsHide: true
      });
      const match = output.match(/InstallPath\s+REG_SZ\s+(.+)/);
      if (match) {
        return match[1].trim();
      }
      return null;
    } catch {
      return null;
    }
  }

  private async tryRegistryInstall(): Promise<boolean> {
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

  private async tryFallbackPath(): Promise<boolean> {
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

  private sha256File(filePath: string): string {
    const buffer = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }

  private async downloadAndVerify(): Promise<string | null> {
    const manifestUrl = 'https://download.getvvault.com/manifest.json';
    let manifest: any;
    try {
      const res = await fetch(manifestUrl);
      if (!res.ok) {
        return null;
      }
      manifest = await res.json();
    } catch {
      return null;
    }

    const assetInfo = manifest['vigil-backend-win-x64.exe'];
    if (!assetInfo || !assetInfo.url || !assetInfo.sha256) {
      return null;
    }

    const storageDir = this.context.globalStorageUri.fsPath;
    if (!fs.existsSync(storageDir)) {
      fs.mkdirSync(storageDir, { recursive: true });
    }
    const destPath = path.join(storageDir, 'Vigil.exe');

    const downloaded = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Vigil: downloading backend (one-time setup)',
        cancellable: false
      },
      async () => {
        try {
          const res = await fetch(assetInfo.url);
          if (!res.ok || !res.body) {
            return false;
          }
          const arrayBuffer = await res.arrayBuffer();
          fs.writeFileSync(destPath, Buffer.from(arrayBuffer));
          return true;
        } catch {
          return false;
        }
      }
    );

    if (!downloaded) {
      return null;
    }

    const actualHash = this.sha256File(destPath);
    if (actualHash.toLowerCase() !== String(assetInfo.sha256).toLowerCase()) {
      try {
        fs.unlinkSync(destPath);
      } catch {
        // ignore cleanup failure
      }
      throw new Error('Vigil backend download failed checksum verification.');
    }

    return destPath;
  }

  private async tryDownloadInstall(): Promise<boolean> {
    this.setState('downloading');
    let exePath: string | null;
    try {
      exePath = await this.downloadAndVerify();
    } catch (err: any) {
      vscode.window.showErrorMessage(
        `Vigil: backend download failed verification (${err.message}). Please install Vigil manually.`
      );
      return false;
    }

    if (!exePath) {
      vscode.window.showInformationMessage(
        'Vigil backend not found. Install from getvvault.com/vigil',
        'Download'
      ).then(selection => {
        if (selection === 'Download') {
          vscode.env.openExternal(
            vscode.Uri.parse('https://getvvault.com/vigil')
          );
        }
      });
      return false;
    }

    this.setState('starting');
    this.spawnDetached(exePath);
    return this.waitForHealth(START_WAIT_TIMEOUT_MS);
  }

  async ensureVigilRunning(): Promise<boolean> {
    if (await this.checkHealth()) {
      this.setState('running');
      await this.loadCapabilities();
      return true;
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

  private async loadCapabilities(): Promise<void> {
    try {
      const res = await fetch(`http://127.0.0.1:${this.port}/capabilities`);
      if (res.ok) {
        this._capabilities = await res.json();
      }
    } catch {
      this._capabilities = null;
    }
  }

  hasCapability(name: string): boolean {
    if (!this._capabilities) {
      return true;
    }
    if (Array.isArray(this._capabilities)) {
      return this._capabilities.includes(name);
    }
    return !!this._capabilities[name];
  }
}
