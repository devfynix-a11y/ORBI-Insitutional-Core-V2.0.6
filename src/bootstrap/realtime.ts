import crypto from 'crypto';
import type { Server as HttpServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { AuthService } from '../../iam/authService.js';
import { SocketRegistry } from '../../backend/infrastructure/SocketRegistry.js';

export const bootstrapRealtime = ({
  httpServer,
  allowedOrigins,
}: {
  httpServer: HttpServer;
  allowedOrigins: string[];
}) => {
  const wss = new WebSocketServer({
    server: httpServer,
    path: '/nexus-stream',
    verifyClient: (info, cb) => {
      const origin = info.origin || info.req.headers.origin;
      if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes(origin.replace('http://', 'https://'))) {
        cb(true);
      } else {
        console.warn(`[Nexus] Rejected connection from unauthorized origin: ${origin}`);
        cb(false, 403, 'Forbidden');
      }
    },
  });

  wss.on('connection', (ws: WebSocket, req) => {
    (ws as any).isAlive = true;
    (ws as any).__socketId = crypto.randomUUID();
    ws.on('pong', () => {
      (ws as any).isAlive = true;
    });

    console.info(`[Nexus] New Node connection from ${req.socket.remoteAddress}`);
    ws.on('message', async (msg) => {
      try {
        const data = JSON.parse(msg.toString());
        if (data.event === 'PING') ws.send(JSON.stringify({ event: 'PONG', ts: Date.now() }));

        if (data.event === 'AUTH') {
          let userId = data.userId;
          if (data.token) {
            try {
              const authService = new AuthService();
              const session = await authService.getSession(data.token);
              if (session) {
                userId = session.user.id;
              }
            } catch (e) {
              console.error('[Nexus] Auth Token Verification Failed', e);
            }
          }

          if (userId) {
            (ws as any).userId = userId;
            SocketRegistry.register(userId, ws);
            ws.send(
              JSON.stringify({
                event: 'AUTH_SUCCESS',
                ts: Date.now(),
                trace: data.trace || undefined,
                connectionSerial: data.connectionSerial || undefined,
                socket_id: (ws as any).__socketId || undefined,
                session_id: userId,
              }),
            );
          }
        }
      } catch {}
    });

    ws.on('close', () => {
      if ((ws as any).userId) {
        SocketRegistry.remove((ws as any).userId, ws);
      }
    });
  });

  const wsPingInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
      if ((ws as any).isAlive === false) return ws.terminate();
      (ws as any).isAlive = false;
      ws.ping();
    });
  }, 30000);

  wss.on('close', () => {
    clearInterval(wsPingInterval);
  });

  return {
    wss,
    stop: async () => {
      clearInterval(wsPingInterval);
      await new Promise<void>((resolve) => {
        wss.close(() => resolve());
      });
    },
  };
};
