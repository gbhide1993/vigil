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
exports.FindingsTreeProvider = exports.RedLineTreeProvider = exports.SessionTreeProvider = exports.VigilTreeItem = void 0;
const vscode = __importStar(require("vscode"));
class VigilTreeItem extends vscode.TreeItem {
    constructor(label, collapsibleState, options) {
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
exports.VigilTreeItem = VigilTreeItem;
class BaseTreeProvider {
    constructor(api) {
        this.api = api;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.rootItems = [];
    }
    getTreeItem(element) {
        return element;
    }
    getChildren(element) {
        if (!element) {
            return this.rootItems;
        }
        return element.children ?? [];
    }
    fireChange() {
        this._onDidChangeTreeData.fire();
    }
}
class SessionTreeProvider extends BaseTreeProvider {
    async refresh() {
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
    buildSessionItems(session) {
        const fileChildren = session.files_touched.map((f) => new VigilTreeItem(f, vscode.TreeItemCollapsibleState.None, { iconPath: new vscode.ThemeIcon('file') }));
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
            new VigilTreeItem(`Files touched (${session.files_touched.length})`, session.files_touched.length > 0
                ? vscode.TreeItemCollapsibleState.Collapsed
                : vscode.TreeItemCollapsibleState.None, { iconPath: new vscode.ThemeIcon('files'), children: fileChildren }),
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
exports.SessionTreeProvider = SessionTreeProvider;
class RedLineTreeProvider extends BaseTreeProvider {
    async refresh() {
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
        this.rootItems = events.map((event) => {
            const time = this.formatTime(event.timestamp);
            const child = new VigilTreeItem(`Process: ${event.process} | File: ${event.filepath}`, vscode.TreeItemCollapsibleState.None);
            return new VigilTreeItem(`[${event.type}] ${event.description} — ${time}`, vscode.TreeItemCollapsibleState.Collapsed, {
                iconPath: new vscode.ThemeIcon('alert'),
                tooltip: `${event.description}\nSeverity: ${event.severity}\nSession: ${event.session_id}`,
                children: [child]
            });
        });
        this.fireChange();
    }
    formatTime(timestamp) {
        try {
            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        }
        catch {
            return timestamp;
        }
    }
}
exports.RedLineTreeProvider = RedLineTreeProvider;
class FindingsTreeProvider extends BaseTreeProvider {
    async refresh() {
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
        this.rootItems = findings.map((finding) => {
            const pct = Math.round((finding.confidence ?? 0) * 100);
            const fileName = finding.filepath.split(/[\\/]/).pop() ?? finding.filepath;
            const child = new VigilTreeItem(finding.description, vscode.TreeItemCollapsibleState.None);
            return new VigilTreeItem(`⚠ ${finding.finding_type} (${pct}%) — ${fileName}`, vscode.TreeItemCollapsibleState.Collapsed, {
                iconPath: new vscode.ThemeIcon('warning'),
                tooltip: `${finding.description}\nSession: ${finding.session_id}`,
                children: [child]
            });
        });
        this.fireChange();
    }
}
exports.FindingsTreeProvider = FindingsTreeProvider;
//# sourceMappingURL=sidebarProvider.js.map