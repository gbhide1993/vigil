import * as vscode from 'vscode';

export class VigilFileDecorationProvider implements vscode.FileDecorationProvider {
  private _onDidChangeFileDecorations = new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>();
  readonly onDidChangeFileDecorations = this._onDidChangeFileDecorations.event;

  private frictionByFile = new Map<string, number>();

  setFrictionData(entries: Map<string, number>) {
    this.frictionByFile = entries;
    this._onDidChangeFileDecorations.fire(undefined);
  }

  provideFileDecoration(uri: vscode.Uri): vscode.ProviderResult<vscode.FileDecoration> {
    const fsPath = uri.fsPath;
    for (const [filepath, count] of this.frictionByFile.entries()) {
      if (fsPath.endsWith(filepath) || fsPath.includes(filepath)) {
        const badge = count > 9 ? '9+' : String(count);
        return {
          badge,
          tooltip: `Vigil: ${count} friction signal(s)`,
          color: new vscode.ThemeColor('list.warningForeground')
        };
      }
    }
    return undefined;
  }
}
