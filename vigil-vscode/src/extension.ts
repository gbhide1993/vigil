import * as vscode from 'vscode';
import { VigilAPI } from './api';
import { BackendManager, releaseLock } from './backendManager';
import { StatusBarManager } from './statusBar';
import { SessionTreeProvider, RedLineTreeProvider, FindingsTreeProvider } from './sidebarProvider';
import { VigilFileDecorationProvider } from './fileDecorator';
import { RedLineWatcher } from './redLineWatcher';

let pollTimer: ReturnType<typeof setInterval> | undefined;

export async function activate(context: vscode.ExtensionContext) {
  console.log('[VIGIL TRACE][activate] entered activate()');
  const config = vscode.workspace.getConfiguration('vigil');
  const port = config.get<number>('apiPort', 7422);
  const pollIntervalSeconds = config.get<number>('pollIntervalSeconds', 10);
  const showFileDecorations = config.get<boolean>('showFileDecorations', true);
  const redLineNotifications = config.get<boolean>('redLineNotifications', true);

  const backendManager = new BackendManager(context, port);
  const api = new VigilAPI(port);

  const statusBar = new StatusBarManager(api, backendManager);
  context.subscriptions.push({ dispose: () => statusBar.dispose() });

  const sessionProvider = new SessionTreeProvider(api);
  const redLineProvider = new RedLineTreeProvider(api);
  const findingsProvider = new FindingsTreeProvider(api);

  context.subscriptions.push(vscode.window.registerTreeDataProvider('vigil.currentSession', sessionProvider));
  context.subscriptions.push(vscode.window.registerTreeDataProvider('vigil.redLines', redLineProvider));
  context.subscriptions.push(vscode.window.registerTreeDataProvider('vigil.findings', findingsProvider));

  let fileDecorationProvider: VigilFileDecorationProvider | undefined;
  if (showFileDecorations) {
    fileDecorationProvider = new VigilFileDecorationProvider();
    context.subscriptions.push(vscode.window.registerFileDecorationProvider(fileDecorationProvider));
  }

  let redLineWatcher: RedLineWatcher | undefined;
  if (redLineNotifications) {
    redLineWatcher = new RedLineWatcher(api, port);
  }

  const refreshAll = async () => {
    await Promise.all([
      statusBar.refresh(),
      (async () => {
        console.log('[VIGIL TRACE][refreshAll] before sessionProvider.refresh()');
        await sessionProvider.refresh();
        console.log('[VIGIL TRACE][refreshAll] after sessionProvider.refresh()');
      })(),
      (async () => {
        console.log('[VIGIL TRACE][refreshAll] before redLineProvider.refresh()');
        await redLineProvider.refresh();
      })(),
      (async () => {
        console.log('[VIGIL TRACE][refreshAll] before findingsProvider.refresh()');
        await findingsProvider.refresh();
      })()
    ]);

    if (fileDecorationProvider) {
      const findings = await api.getFrictionFindings();
      const counts = new Map<string, number>();
      for (const finding of findings) {
        if (!finding.filepath) {
          continue;
        }
        counts.set(finding.filepath, (counts.get(finding.filepath) ?? 0) + 1);
      }
      fileDecorationProvider.setFrictionData(counts);
    }

    if (redLineWatcher) {
      await redLineWatcher.poll();
    }
  };

  context.subscriptions.push(
    vscode.commands.registerCommand('vigil.openDashboard', () => {
      vscode.env.openExternal(vscode.Uri.parse(`http://127.0.0.1:${port}`));
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('vigil.refresh', async () => {
      await refreshAll();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('vigil.copyEvidenceHash', async () => {
      const summary = await api.getEvidenceSummary();
      if (!summary || !summary.evidence_hash) {
        vscode.window.showErrorMessage('Vigil: no evidence hash available.');
        return;
      }
      await vscode.env.clipboard.writeText(summary.evidence_hash);
      vscode.window.showInformationMessage('Evidence hash copied');
    })
  );

  console.log('[VIGIL TRACE][activate] before await backendManager.ensureVigilRunning()');
  const running = await backendManager.ensureVigilRunning();
  console.log(
    `[VIGIL TRACE][activate] after ensureVigilRunning() running=${running} backendState=${backendManager.state}`
  );

  if (running) {
    const welcomed = context.globalState.get<boolean>('vigil.welcomed', false);
    if (!welcomed) {
      vscode.window.showInformationMessage('👁 Vigil connected — monitoring your AI coding sessions.');
      await context.globalState.update('vigil.welcomed', true);
    }
  }

  console.log('[VIGIL TRACE][activate] before await refreshAll()');
  await refreshAll();
  console.log('[VIGIL TRACE][activate] after refreshAll()');

  pollTimer = setInterval(refreshAll, pollIntervalSeconds * 1000);
  context.subscriptions.push({
    dispose: () => {
      if (pollTimer) {
        clearInterval(pollTimer);
      }
    }
  });

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => {
      refreshAll();
    })
  );
}

export function deactivate() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = undefined;
  }
  releaseLock();
}
