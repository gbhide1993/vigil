import * as vscode from 'vscode';
import { VigilAPI, SessionStatus } from './api';
import { BackendManager, BackendState } from './backendManager';

export class StatusBarManager {
  private item: vscode.StatusBarItem;

  constructor(private api: VigilAPI, private backendManager: BackendManager) {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.command = 'vigil.openDashboard';
    this.item.show();
  }

  dispose() {
    this.item.dispose();
  }

  private setDownloading() {
    this.item.text = '$(cloud-download) Vigil: Setting up...';
    this.item.tooltip = 'Downloading Vigil — one-time setup';
    this.item.backgroundColor = undefined;
  }

  private setStarting() {
    this.item.text = '$(loading~spin) Vigil: Starting...';
    this.item.tooltip = 'Vigil backend is starting';
    this.item.backgroundColor = undefined;
  }

  private setRedLine(session: SessionStatus) {
    this.item.text = '$(alert) Vigil: Red Line';
    this.item.tooltip = 'Red Line alert — click to open Vigil';
    this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  }

  private sessionTooltip(session: SessionStatus): string {
    return [
      `Session: ${session.session_id}`,
      `Agent: ${session.agent}`,
      `Duration: ${session.duration_min} min`,
      `Files touched: ${session.files_touched.length}`,
      `Friction signals: ${session.friction_signals}`,
      `Red Lines: ${session.red_lines}`,
      '',
      'Click to open Vigil dashboard'
    ].join('\n');
  }

  private setActiveFriction(session: SessionStatus) {
    this.item.text = `$(eye) Vigil: ${session.duration_min}m $(warning)`;
    this.item.tooltip = this.sessionTooltip(session);
    this.item.backgroundColor = undefined;
  }

  private setActiveClean(session: SessionStatus) {
    this.item.text = `$(eye) Vigil: ${session.duration_min}m $(check)`;
    this.item.tooltip = this.sessionTooltip(session);
    this.item.backgroundColor = undefined;
  }

  private setReady() {
    this.item.text = '$(eye) Vigil: Ready';
    this.item.tooltip = 'Vigil is running — start an AI coding session';
    this.item.backgroundColor = undefined;
  }

  private setOffline() {
    this.item.text = '$(eye-closed) Vigil: Offline';
    this.item.tooltip = 'Vigil is not running';
    this.item.backgroundColor = undefined;
  }

  async refresh(): Promise<void> {
    const state: BackendState = this.backendManager.state;

    if (state === 'downloading') {
      this.setDownloading();
      return;
    }
    if (state === 'starting') {
      this.setStarting();
      return;
    }

    const online = await this.api.isOnline();
    if (!online) {
      this.setOffline();
      return;
    }

    const session = await this.api.getCurrentSession();
    if (!session || !session.active) {
      this.setReady();
      return;
    }

    if (session.red_lines > 0) {
      this.setRedLine(session);
      return;
    }

    if (session.friction_signals > 0) {
      this.setActiveFriction(session);
      return;
    }

    this.setActiveClean(session);
  }
}
