import * as vscode from 'vscode';
import { VigilAPI, RedLineEvent } from './api';

export class RedLineWatcher {
  private seenEventIds = new Set<string>();
  private initialized = false;

  constructor(private api: VigilAPI, private port: number) {}

  async poll(): Promise<void> {
    const events = await this.api.getRedLineEvents(1);
    if (!events || events.length === 0) {
      return;
    }

    const newEvents = events.filter((e) => !this.seenEventIds.has(e.event_id));
    for (const event of events) {
      this.seenEventIds.add(event.event_id);
    }

    if (!this.initialized) {
      this.initialized = true;
      return;
    }

    for (const event of newEvents) {
      this.notify(event);
    }
  }

  private notify(event: RedLineEvent) {
    vscode.window
      .showWarningMessage(`🔴 Vigil Red Line: ${event.description}`, 'View Evidence')
      .then((selection) => {
        if (selection === 'View Evidence') {
          vscode.env.openExternal(vscode.Uri.parse(`http://127.0.0.1:${this.port}`));
        }
      });
  }
}
