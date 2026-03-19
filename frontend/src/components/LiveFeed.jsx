import { useState, useEffect, useRef } from 'react';
import { connectWebSocket } from '../websocket.js';

const LiveFeed = () => {
  const [messages, setMessages] = useState([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    const ws = connectWebSocket('global', {
      onOpen: () => setConnected(true),
      onClose: () => setConnected(false),
      onMessage: (data) => {
        setMessages(prev => [data, ...prev.slice(0, 49)]);
      },
    });
    wsRef.current = ws;
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const formatMessage = (msg) => {
    if (msg.type === 'finding') {
      return `New finding: ${msg.data.severity} - ${msg.data.type}`;
    } else if (msg.type === 'progress') {
      return `Progress: ${msg.data.phase} ${msg.data.completed}/${msg.data.total}`;
    } else if (msg.type === 'log') {
      return `Log: ${msg.data}`;
    }
    return JSON.stringify(msg);
  };

  return (
    <div className="card bg-base-200 shadow">
      <div className="card-body">
        <div className="flex justify-between items-center">
          <h2 className="card-title">Live Feed</h2>
          <div className="flex items-center gap-2">
            <div className={`badge ${connected ? 'badge-success' : 'badge-error'}`}>
              {connected ? 'Connected' : 'Disconnected'}
            </div>
            <button
              className="btn btn-xs"
              onClick={() => setMessages([])}
            >
              Clear
            </button>
          </div>
        </div>
        <div className="h-64 overflow-y-auto bg-base-300 rounded p-2">
          {messages.length === 0 ? (
            <div className="text-center text-base-content/60 p-4">
              No live events yet.
            </div>
          ) : (
            messages.map((msg, idx) => (
              <div
                key={idx}
                className="p-2 border-b border-base-content/10"
              >
                <span className="text-xs opacity-70">
                  {new Date().toLocaleTimeString()}
                </span>
                <span className="ml-2">{formatMessage(msg)}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default LiveFeed;