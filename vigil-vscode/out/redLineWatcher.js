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
exports.RedLineWatcher = void 0;
const vscode = __importStar(require("vscode"));
class RedLineWatcher {
    constructor(api, port) {
        this.api = api;
        this.port = port;
        this.seenEventIds = new Set();
        this.initialized = false;
    }
    async poll() {
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
    notify(event) {
        vscode.window
            .showWarningMessage(`🔴 Vigil Red Line: ${event.description}`, 'View Evidence')
            .then((selection) => {
            if (selection === 'View Evidence') {
                vscode.env.openExternal(vscode.Uri.parse(`http://127.0.0.1:${this.port}`));
            }
        });
    }
}
exports.RedLineWatcher = RedLineWatcher;
//# sourceMappingURL=redLineWatcher.js.map