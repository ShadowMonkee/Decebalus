export interface WebSocketOptions {
  onOpen?: (event: Event) => void;
  onMessage?: (data: any) => void;
  onClose?: (event: CloseEvent) => void;
  reconnect?: boolean;
  reconnectDelay?: number;
}

/**
 * A lightweight WebSocket wrapper with auto-reconnect and typed handlers.
 */
export class WebSocketClient {
  private url: string;
  private ws: WebSocket | null = null;
  private onOpen: (event: Event) => void;
  private onMessage: (data: any) => void;
  private onClose: (event: CloseEvent) => void;
  private reconnect: boolean;
  private reconnectDelay: number;

  constructor(url: string, options: WebSocketOptions = {}) {
    this.url = url;
    this.onOpen = options.onOpen ?? (() => {});
    this.onMessage = options.onMessage ?? (() => {});
    this.onClose = options.onClose ?? (() => {});
    this.reconnect = options.reconnect ?? true;
    this.reconnectDelay = options.reconnectDelay ?? 3000;
  }

  /** Connect to the WebSocket server */
  public connect(): void {
    this.ws = new WebSocket(this.url);

    this.ws.onopen = (event) => this.onOpen(event);
    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.onMessage(data);
      } catch {
        this.onMessage(event.data);
      }
    };
    this.ws.onclose = (event) => {
      this.onClose(event);
      if (this.reconnect) {
        console.log(`Reconnecting in ${this.reconnectDelay / 1000}s...`);
        setTimeout(() => this.connect(), this.reconnectDelay);
      }
    };
  }

  /** Send data (auto-stringified if not string) */
  public send(data: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(typeof data === "string" ? data : JSON.stringify(data));
    } else {
      console.warn("WebSocket not open. Message not sent:", data);
    }
  }

  /** Close the connection and disable auto-reconnect */
  public close(): void {
    this.reconnect = false;
    this.ws?.close();
  }

  /** Get the current readyState (or undefined if not connected) */
  public get readyState(): number | undefined {
    return this.ws?.readyState ?? WebSocket.CLOSED;
  }

  /** Check if the WebSocket is currently open */
  public get isOpen(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}
