import { io, Socket } from 'socket.io-client';
import { WebSocketMessage, Device, Command } from './types';
import Cookies from 'js-cookie';

type EventCallback<T = any> = (data: T) => void;

class WebSocketClient {
  private socket: Socket | null = null;
  private url: string;
  private isConnected = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private callbacks: Map<string, EventCallback[]> = new Map();

  constructor() {
    this.url = process.env.NEXT_PUBLIC_WS_URL || 'http:
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.socket && this.isConnected) {
        resolve();
        return;
      }

      const token = Cookies.get('auth_token');
      if (!token) {
        reject(new Error('No authentication token found'));
        return;
      }

      this.socket = io(this.url, {
        auth: {
          token: token,
        },
        transports: ['websocket'],
        upgrade: true,
      });

      this.socket.on('connect', () => {
        console.log('WebSocket connected');
        this.isConnected = true;
        this.reconnectAttempts = 0;
        resolve();
      });

      this.socket.on('disconnect', (reason) => {
        console.log('WebSocket disconnected:', reason);
        this.isConnected = false;
        this.handleReconnect();
      });

      this.socket.on('connect_error', (error) => {
        console.error('WebSocket connection error:', error);
        this.isConnected = false;

        if (error.message.includes('401') || error.message.includes('unauthorized')) {

          Cookies.remove('auth_token');
          window.location.href = '/login';
          reject(error);
          return;
        }

        this.handleReconnect();
        reject(error);
      });

      this.setupMessageHandlers();

      setTimeout(() => {
        if (!this.isConnected) {
          reject(new Error('WebSocket connection timeout'));
        }
      }, 10000);
    });
  }

  private setupMessageHandlers(): void {
    if (!this.socket) return;

    this.socket.on('device_status', (data: Device) => {
      this.emit('device_status', data);
    });

    this.socket.on('command_result', (data: Command) => {
      this.emit('command_result', data);
    });

    this.socket.on('new_data', (data: { type: string; deviceId: string; count: number }) => {
      this.emit('new_data', data);
    });

    this.socket.on('error', (data: { message: string; deviceId?: string }) => {
      this.emit('error', data);
    });

    this.socket.on('notification', (data: { type: string; title: string; message: string }) => {
      this.emit('notification', data);
    });
  }

  private handleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      this.emit('connection_failed', { message: 'Unable to establish connection after multiple attempts' });
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

    setTimeout(() => {
      if (!this.isConnected) {
        this.connect().catch((error) => {
          console.error('Reconnection failed:', error);
        });
      }
    }, delay);
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.isConnected = false;
    this.callbacks.clear();
  }

  subscribeToDevice(deviceId: string): void {
    if (this.socket && this.isConnected) {
      this.socket.emit('subscribe_device', { deviceId });
    }
  }

  unsubscribeFromDevice(deviceId: string): void {
    if (this.socket && this.isConnected) {
      this.socket.emit('unsubscribe_device', { deviceId });
    }
  }

  subscribeToCampaign(campaignId: string): void {
    if (this.socket && this.isConnected) {
      this.socket.emit('subscribe_campaign', { campaignId });
    }
  }

  unsubscribeFromCampaign(campaignId: string): void {
    if (this.socket && this.isConnected) {
      this.socket.emit('unsubscribe_campaign', { campaignId });
    }
  }

  on<T = any>(event: string, callback: EventCallback<T>): void {
    if (!this.callbacks.has(event)) {
      this.callbacks.set(event, []);
    }
    this.callbacks.get(event)!.push(callback);
  }

  off(event: string, callback?: EventCallback): void {
    if (!this.callbacks.has(event)) return;

    if (callback) {
      const callbacks = this.callbacks.get(event)!;
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    } else {
      this.callbacks.delete(event);
    }
  }

  private emit<T = any>(event: string, data: T): void {
    const callbacks = this.callbacks.get(event);
    if (callbacks) {
      callbacks.forEach(callback => callback(data));
    }
  }

  send(event: string, data: any): void {
    if (this.socket && this.isConnected) {
      this.socket.emit(event, data);
    } else {
      console.warn('WebSocket not connected, cannot send message:', event, data);
    }
  }

  get connected(): boolean {
    return this.isConnected;
  }

  get connectionState(): 'connected' | 'connecting' | 'disconnected' | 'error' {
    if (!this.socket) return 'disconnected';

    if (this.socket.connected) return 'connected';
    if (this.socket.connecting) return 'connecting';
    if (this.reconnectAttempts > 0 && this.reconnectAttempts < this.maxReconnectAttempts) return 'connecting';

    return 'disconnected';
  }
}

export const wsClient = new WebSocketClient();
export default wsClient;