import { useEffect, useRef, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import { Notification, JobProgressUpdate } from '@devsecops/shared/types';
import { currentAccessToken } from '../lib/session';
import { websocketOrigin } from '../lib/runtimeConfig';

interface UseWebSocketOptions {
  onNotification?: (notification: Notification) => void;
  onJobUpdate?: (update: JobProgressUpdate) => void;
  onScanUpdate?: (update: { scanId: string; status: string; progress: number }) => void;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { isAuthenticated } = useAuth();
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const lastMessageRef = useRef<any>(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;

  const connect = useCallback(() => {
    const accessToken = currentAccessToken();
    if (!isAuthenticated || !accessToken) return;

    const wsUrl = `${websocketOrigin()}/ws?token=${encodeURIComponent(accessToken)}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('WebSocket connected');
      reconnectAttempts.current = 0;
      // Subscribe to channels
      ws.send(JSON.stringify({
        type: 'subscribe',
        payload: { channels: ['notifications', 'jobs', 'scans'] }
      }));
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        lastMessageRef.current = message;

        switch (message.type) {
          case 'notification':
            options.onNotification?.(message.payload);
            break;
          case 'job_update':
            options.onJobUpdate?.(message.payload);
            break;
          case 'scan_update':
            options.onScanUpdate?.(message.payload);
            break;
        }
      } catch (err) {
        console.error('WebSocket message parse error:', err);
      }
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
      if (reconnectAttempts.current < maxReconnectAttempts) {
        const delay = Math.min(1000 * 2 ** reconnectAttempts.current, 30000);
        reconnectTimeoutRef.current = setTimeout(() => {
          reconnectAttempts.current++;
          connect();
        }, delay);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }, [isAuthenticated, options]);

  useEffect(() => {
    if (isAuthenticated) {
      connect();
    } else {
      wsRef.current?.close();
    }

    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      wsRef.current?.close();
    };
  }, [connect, isAuthenticated]);

  const send = useCallback((message: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    }
  }, []);

  const subscribe = useCallback((channels: string[]) => {
    send({ type: 'subscribe', payload: { channels } });
  }, [send]);

  const unsubscribe = useCallback((channels: string[]) => {
    send({ type: 'unsubscribe', payload: { channels } });
  }, [send]);

  return {
    lastMessage: lastMessageRef.current,
    send,
    subscribe,
    unsubscribe,
    isConnected: wsRef.current?.readyState === WebSocket.OPEN
  };
}