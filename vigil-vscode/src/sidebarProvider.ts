import * as vscode from 'vscode';
import { VigilAPI, SessionStatus, RedLineEvent, FrictionFinding } from './api';

export class VigilTreeItem extends vscode.TreeItem {
  children?: VigilTreeItem[];

  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    options?: { description?: string; tooltip?: string; iconPath?: vscode.ThemeIcon; children?: VigilTreeItem[] }
  ) {
    super(label, collapsibleState);
    if (options?.description) {
      this.description = options.description;
    }
    if (options?.tooltip) {
      this.tooltip = options.tooltip;
    }
    if (options?.iconPath) {
      this.iconPath = options.iconPath;
    }
    this.children = options?.children;
  }
}

abstract class BaseTreeProvider implements vscode.TreeDataProvider<VigilTreeItem> {
  protected _onDidChangeTreeData = new vscode.EventEmitter<VigilTreeItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  protected rootItems: VigilTreeItem[] = [];

  constructor(protected api: VigilAPI) {}

  getTreeItem(element: VigilTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: VigilTreeItem): vscode.ProviderResult<VigilTreeItem[]> {
    if (!element) {
      return this.rootItems;
    }
    return element.children ?? [];
  }

  abstract refresh(): Promise<void>;

  protected fireChange() {
    this._onDidChangeTreeData.fire();
  }
}

export class SessionTreeProvider extends BaseTreeProvider {
  async refresh(): Promise<void> {
    const online = await this.api.isOnline();
    if (!online) {
      this.rootItems = [
        new VigilTreeItem('Vigil is not running', vscode.TreeItemCollapsibleState.None, {
          iconPath: new vscode.ThemeIcon('eye-closed')
        })
      ];
      this.fireChange();
      return;
    }

    const session = await this.api.getCurrentSession();
    if (!session || !session.active) {
      this.rootItems = [
        new VigilTreeItem('No active session', vscode.TreeItemCollapsibleState.None, {
          iconPath: new vscode.ThemeIcon('circle-slash')
        })
      ];
      this.fireChange();
      return;
    }

    this.rootItems = this.buildSessionItems(session);
    this.fireChange();
  }

  private buildSessionItems(session: SessionStatus): VigilTreeItem[] {
    const fileChildren = session.files_touched.map(
      (f) => new VigilTreeItem(f, vscode.TreeItemCollapsibleState.None, { iconPath: new vscode.ThemeIcon('file') })
    );

    return [
      new VigilTreeItem('Agent', vscode.TreeItemCollapsibleState.None, {
        description: session.agent ?? 'Unknown',
        iconPath: new vscode.ThemeIcon('robot')
      }),
      new VigilTreeItem('Duration', vscode.TreeItemCollapsibleState.None, {
        description: `${session.duration_min} min`,
        iconPath: new vscode.ThemeIcon('clock')
      }),
      new VigilTreeItem('Status', vscode.TreeItemCollapsibleState.None, {
        description: session.status,
        iconPath: new vscode.ThemeIcon('pulse')
      }),
      new VigilTreeItem(
        `Files touched (${session.files_touched.length})`,
        session.files_touched.length > 0
          ? vscode.TreeItemCollapsibleState.Collapsed
          : vscode.TreeItemCollapsibleState.None,
        { iconPath: new vscode.ThemeIcon('files'), children: fileChildren }
      ),
      new VigilTreeItem('Friction Signals', vscode.TreeItemCollapsibleState.None, {
        description: String(session.friction_signals),
        iconPath: new vscode.ThemeIcon('warning')
      }),
      new VigilTreeItem('Red Lines', vscode.TreeItemCollapsibleState.None, {
        description: String(session.red_lines),
        iconPath: new vscode.ThemeIcon('alert')
      })
    ];
  }
}

export class RedLineTreeProvider extends BaseTreeProvider {
  async refresh(): Promise<void> {
    const online = await this.api.isOnline();
    if (!online) {
      this.rootItems = [
        new VigilTreeItem('Vigil is not running', vscode.TreeItemCollapsibleState.None, {
          iconPath: new vscode.ThemeIcon('eye-closed')
        })
      ];
      this.fireChange();
      return;
    }

    const events = await this.api.getRedLineEvents(24);
    if (!events || events.length === 0) {
      this.rootItems = [
        new VigilTreeItem('No Red Lines in last 24h ✓', vscode.TreeItemCollapsibleState.None, {
          iconPath: new vscode.ThemeIcon('check')
        })
      ];
      this.fireChange();
      return;
    }

    this.rootItems = events.map((event: RedLineEvent) => {
      const time = this.formatTime(event.timestamp);
      const child = new VigilTreeItem(
        `Process: ${event.process} | File: ${event.filepath}`,
        vscode.TreeItemCollapsibleState.None
      );
      return new VigilTreeItem(
        `[${event.type}] ${event.description} — ${time}`,
        vscode.TreeItemCollapsibleState.Collapsed,
        {
          iconPath: new vscode.ThemeIcon('alert'),
          tooltip: `${event.description}\nSeverity: ${event.severity}\nSession: ${event.session_id}`,
          children: [child]
        }
      );
    });
    this.fireChange();
  }

  private formatTime(timestamp: string): string {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString();
    } catch {
      return timestamp;
    }
  }
}

export class FindingsTreeProvider extends BaseTreeProvider {
  async refresh(): Promise<void> {
    const online = await this.api.isOnline();
    if (!online) {
      this.rootItems = [
        new VigilTreeItem('Vigil is not running', vscode.TreeItemCollapsibleState.None, {
          iconPath: new vscode.ThemeIcon('eye-closed')
        })
      ];
      this.fireChange();
      return;
    }

    const findings = await this.api.getFrictionFindings();
    if (!findings || findings.length === 0) {
      this.rootItems = [
        new VigilTreeItem('No friction findings ✓', vscode.TreeItemCollapsibleState.None, {
          iconPath: new vscode.ThemeIcon('check')
        })
      ];
      this.fireChange();
      return;
    }

    this.rootItems = findings.map((finding: FrictionFinding) => {
      const pct = Math.round((finding.confidence ?? 0) * 100);
      const fileName = finding.filepath.split(/[\\/]/).pop() ?? finding.filepath;
      const child = new VigilTreeItem(finding.description, vscode.TreeItemCollapsibleState.None);
      return new VigilTreeItem(
        `⚠ ${finding.finding_type} (${pct}%) — ${fileName}`,
        vscode.TreeItemCollapsibleState.Collapsed,
        {
          iconPath: new vscode.ThemeIcon('warning'),
          tooltip: `${finding.description}\nSession: ${finding.session_id}`,
          children: [child]
        }
      );
    });
    this.fireChange();
  }
}
