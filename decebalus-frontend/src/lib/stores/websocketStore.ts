import { writable } from 'svelte/store';
import { WebSocketClient } from './websocket';

// Create stores (reactive containers)
export const websocket = writable<WebSocketClient | null>(null);
export const connectionStatus = writable<'connected' | 'connecting' | 'disconnected'>('disconnected');
let activeConnection: WebSocketClient | null = null;


// Function that connects and updates the stores
export function connectWebSocket() {

  if (activeConnection && activeConnection.readyState === WebSocket.OPEN) {
    console.log('Reusing existing connection');
    return activeConnection;
  }

  // Create your WebSocket client
  const ws = new WebSocketClient('ws://localhost:3000/ws', {
    onOpen: () => connectionStatus.set('connected'),
    onClose: () => connectionStatus.set('disconnected'),
  });

  // While connecting
  connectionStatus.set('connecting');

  // Actually connect
  ws.connect();
  activeConnection = ws;

  // Save the active WebSocket instance in the store
  websocket.set(ws);

  return ws;
}

// Function to disconnect safely
export function closeWebSocket() {
  websocket.update((ws) => {
    ws?.close(); // close connection if open
    return null;
  });
  connectionStatus.set('disconnected');
}
