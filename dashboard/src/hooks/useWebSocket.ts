import { useState, useEffect, useRef, useCallback } from 'react';
import type { Alert } from '@/types';

const MAX_ALERTS = 100;
const RECONNECT_DELAY = 3000;
const MAX_RECONNECT_ATTEMPTS = 10;

interface UseWebSocketReturn {
  alerts: Alert[];
  connected: boolean;
  reconnecting: boolean;
}

export function useWebSocket(): UseWebSocketReturn {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const attemptsRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout>>();

  const getWsUrl = useCallback(() => {
    const apiUrl = import.meta.env.VITE_API_URL;
    if (apiUrl) {
      return apiUrl.replace(/^http/, 'ws') + '/ws/alerts';
    }
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/ws/alerts`;
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(getWsUrl());
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setReconnecting(false);
        attemptsRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const alert: Alert = {
            id: data.id || crypto.randomUUID(),
            ruleId: data.rule_id || data.ruleId || 'unknown',
            level: data.level || 0,
            description: data.description || data.full_log || '',
            agent: data.agent?.name || data.agent || 'unknown',
            timestamp: data.timestamp || new Date().toISOString(),
            mitreTactics: data.mitre?.tactic || data.mitreTactics || [],
            mitreTechniques: data.mitre?.id ? [data.mitre.id] : data.mitreTechniques || [],
          };
          setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onclose = () => {
        setConnected(false);
        wsRef.current = null;

        if (attemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
          setReconnecting(true);
          attemptsRef.current += 1;
          reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY);
        } else {
          setReconnecting(false);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      setConnected(false);
      if (attemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
        setReconnecting(true);
        attemptsRef.current += 1;
        reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY);
      }
    }
  }, [getWsUrl]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { alerts, connected, reconnecting };
}
