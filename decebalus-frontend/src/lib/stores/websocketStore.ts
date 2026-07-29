import { writable } from 'svelte/store';
import { WebSocketClient } from './websocket';

export const connectionStatus = writable<'connected' | 'connecting' | 'disconnected'>('disconnected');

// Legacy colon-delimited progress strings (e.g. "job_completed:<id>"). Existing
// pages subscribe here and pattern-match string prefixes — this stays string-only.
export const wsMessages = writable<string | null>(null);

/** A structured event envelope: { type, payload }. */
export type WsEvent = { type: string; payload: any };

// Typed JSON events (finding | cred | job | engine) for the war table. Kept
// separate from wsMessages so string consumers never receive an object.
export const wsEvents = writable<WsEvent | null>(null);

/** Route an incoming (already JSON-parsed-or-string) message to the right store. */
function routeMessage(data: unknown): void {
  if (data && typeof data === 'object' && typeof (data as any).type === 'string') {
    wsEvents.set(data as WsEvent);
  } else if (typeof data === 'string') {
    wsMessages.set(data);
  }
}

let activeConnection: WebSocketClient | null = null;

export function connectWebSocket(): WebSocketClient {
  if (activeConnection && activeConnection.readyState === WebSocket.OPEN) {
    return activeConnection;
  }

  // Relative URL works in dev (Vite proxies /ws) and in prod (served from same host)
  const wsUrl = `ws://${window.location.host}/ws`;

  const ws = new WebSocketClient(wsUrl, {
    onOpen:    () => connectionStatus.set('connected'),
    onClose:   () => connectionStatus.set('disconnected'),
    onMessage: (data) => routeMessage(data),
  });

  connectionStatus.set('connecting');
  ws.connect();
  activeConnection = ws;
  return ws;
}

export function closeWebSocket(): void {
  activeConnection?.close();
  activeConnection = null;
  connectionStatus.set('disconnected');
}
