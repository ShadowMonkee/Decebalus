import { writable } from 'svelte/store';
import { WebSocketClient } from './websocket';

export const connectionStatus = writable<'connected' | 'connecting' | 'disconnected'>('disconnected');

// Every incoming WS message is pushed here. Pages subscribe to this store.
export const wsMessages = writable<string | object | null>(null);

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
    onMessage: (data) => wsMessages.set(data),
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
