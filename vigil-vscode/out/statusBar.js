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
exports.StatusBarManager = void 0;
const vscode = __importStar(require("vscode"));
class StatusBarManager {
    constructor(api, backendManager) {
        this.api = api;
        this.backendManager = backendManager;
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.item.command = 'vigil.openDashboard';
        this.item.show();
    }
    dispose() {
        this.item.dispose();
    }
    setDownloading() {
        this.item.text = '$(cloud-download) Vigil: Setting up...';
        this.item.tooltip = 'Downloading Vigil — one-time setup';
        this.item.backgroundColor = undefined;
    }
    setStarting() {
        this.item.text = '$(loading~spin) Vigil: Starting...';
        this.item.tooltip = 'Vigil backend is starting';
        this.item.backgroundColor = undefined;
    }
    setRedLine(session) {
        this.item.text = '$(alert) Vigil: Red Line';
        this.item.tooltip = 'Red Line alert — click to open Vigil';
        this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    }
    sessionTooltip(session) {
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
    setActiveFriction(session) {
        this.item.text = `$(eye) Vigil: ${session.duration_min}m $(warning)`;
        this.item.tooltip = this.sessionTooltip(session);
        this.item.backgroundColor = undefined;
    }
    setActiveClean(session) {
        this.item.text = `$(eye) Vigil: ${session.duration_min}m $(check)`;
        this.item.tooltip = this.sessionTooltip(session);
        this.item.backgroundColor = undefined;
    }
    setReady() {
        this.item.text = '$(eye) Vigil: Ready';
        this.item.tooltip = 'Vigil is running — start an AI coding session';
        this.item.backgroundColor = undefined;
    }
    setOffline() {
        this.item.text = '$(eye-closed) Vigil: Offline';
        this.item.tooltip = 'Vigil is not running';
        this.item.backgroundColor = undefined;
    }
    async refresh() {
        const state = this.backendManager.state;
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
exports.StatusBarManager = StatusBarManager;
//# sourceMappingURL=statusBar.js.map