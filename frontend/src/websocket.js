export const connectWebSocket = (scanId, callbacks = {}) => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  const wsUrl = `${protocol}//${host}/ws/${scanId}`;
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log(`WebSocket connected to ${scanId}`);
    callbacks.onOpen?.();
  };

  ws.onclose = () => {
    console.log(`WebSocket disconnected from ${scanId}`);
    callbacks.onClose?.();
    // Attempt reconnect after 3 seconds
    setTimeout(() => {
      connectWebSocket(scanId, callbacks);
    }, 3000);
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      callbacks.onMessage?.(data);
    } catch (e) {
      console.error('Failed to parse WebSocket message:', e);
    }
  };

  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
    callbacks.onError?.(error);
  };

  return ws;
};
