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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const api_1 = require("./api");
const backendManager_1 = require("./backendManager");
const statusBar_1 = require("./statusBar");
const sidebarProvider_1 = require("./sidebarProvider");
const fileDecorator_1 = require("./fileDecorator");
const redLineWatcher_1 = require("./redLineWatcher");
let pollTimer;
async function activate(context) {
    const config = vscode.workspace.getConfiguration('vigil');
    const port = config.get('apiPort', 7422);
    const pollIntervalSeconds = config.get('pollIntervalSeconds', 10);
    const showFileDecorations = config.get('showFileDecorations', true);
    const redLineNotifications = config.get('redLineNotifications', true);
    const backendManager = new backendManager_1.BackendManager(context, port);
    const api = new api_1.VigilAPI(port);
    const statusBar = new statusBar_1.StatusBarManager(api, backendManager);
    context.subscriptions.push({ dispose: () => statusBar.dispose() });
    const sessionProvider = new sidebarProvider_1.SessionTreeProvider(api);
    const redLineProvider = new sidebarProvider_1.RedLineTreeProvider(api);
    const findingsProvider = new sidebarProvider_1.FindingsTreeProvider(api);
    context.subscriptions.push(vscode.window.registerTreeDataProvider('vigil.currentSession', sessionProvider));
    context.subscriptions.push(vscode.window.registerTreeDataProvider('vigil.redLines', redLineProvider));
    context.subscriptions.push(vscode.window.registerTreeDataProvider('vigil.findings', findingsProvider));
    let fileDecorationProvider;
    if (showFileDecorations) {
        fileDecorationProvider = new fileDecorator_1.VigilFileDecorationProvider();
        context.subscriptions.push(vscode.window.registerFileDecorationProvider(fileDecorationProvider));
    }
    let redLineWatcher;
    if (redLineNotifications) {
        redLineWatcher = new redLineWatcher_1.RedLineWatcher(api, port);
    }
    const refreshAll = async () => {
        await Promise.all([
            statusBar.refresh(),
            sessionProvider.refresh(),
            redLineProvider.refresh(),
            findingsProvider.refresh()
        ]);
        if (fileDecorationProvider) {
            const findings = await api.getFrictionFindings();
            const counts = new Map();
            for (const finding of findings) {
                counts.set(finding.filepath, (counts.get(finding.filepath) ?? 0) + 1);
            }
            fileDecorationProvider.setFrictionData(counts);
        }
        if (redLineWatcher) {
            await redLineWatcher.poll();
        }
    };
    context.subscriptions.push(vscode.commands.registerCommand('vigil.openDashboard', () => {
        vscode.env.openExternal(vscode.Uri.parse(`http://127.0.0.1:${port}`));
    }));
    context.subscriptions.push(vscode.commands.registerCommand('vigil.refresh', async () => {
        await refreshAll();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('vigil.copyEvidenceHash', async () => {
        const summary = await api.getEvidenceSummary();
        if (!summary || !summary.evidence_hash) {
            vscode.window.showErrorMessage('Vigil: no evidence hash available.');
            return;
        }
        await vscode.env.clipboard.writeText(summary.evidence_hash);
        vscode.window.showInformationMessage('Evidence hash copied');
    }));
    const running = await backendManager.ensureVigilRunning();
    if (running) {
        const welcomed = context.globalState.get('vigil.welcomed', false);
        if (!welcomed) {
            vscode.window.showInformationMessage('👁 Vigil connected — monitoring your AI coding sessions.');
            await context.globalState.update('vigil.welcomed', true);
        }
    }
    await refreshAll();
    pollTimer = setInterval(refreshAll, pollIntervalSeconds * 1000);
    context.subscriptions.push({
        dispose: () => {
            if (pollTimer) {
                clearInterval(pollTimer);
            }
        }
    });
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(() => {
        refreshAll();
    }));
}
function deactivate() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = undefined;
    }
}
//# sourceMappingURL=extension.js.map