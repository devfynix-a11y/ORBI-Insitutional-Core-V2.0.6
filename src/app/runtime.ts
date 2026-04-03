import express from 'express';
import { createServer as createHttpServer } from 'http';
import { createServer as createHttpsServer } from 'https';
import fs from 'fs';
import multer from 'multer';

export const createRuntime = () => {
  const app = express();
  const tlsEnabled = String(process.env.ORBI_TLS_ENABLED || '').trim().toLowerCase() === 'true';
  const tlsKeyPath = String(process.env.ORBI_TLS_KEY_PATH || '').trim();
  const tlsCertPath = String(process.env.ORBI_TLS_CERT_PATH || '').trim();
  const tlsCaPath = String(process.env.ORBI_TLS_CA_PATH || '').trim();
  const internalMtlsSource = String(process.env.ORBI_INTERNAL_MTLS_SOURCE || '').trim().toLowerCase();
  const internalMtlsCaPath = String(process.env.ORBI_INTERNAL_MTLS_CA_PATH || '').trim();
  const tlsRejectUnauthorized =
    String(process.env.ORBI_TLS_REJECT_UNAUTHORIZED || 'true').trim().toLowerCase() !== 'false';
  const requestClientCert = internalMtlsSource === 'direct';

  const httpServer = tlsEnabled
    ? createHttpsServer(
        {
          key: fs.readFileSync(tlsKeyPath),
          cert: fs.readFileSync(tlsCertPath),
          ca: requestClientCert
            ? fs.readFileSync(internalMtlsCaPath || tlsCaPath)
            : (tlsCaPath ? fs.readFileSync(tlsCaPath) : undefined),
          requestCert: requestClientCert,
          rejectUnauthorized: requestClientCert ? false : tlsRejectUnauthorized,
          minVersion: 'TLSv1.2',
        },
        app,
      )
    : createHttpServer(app);
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 20 * 1024 * 1024 },
  });
  const port = Number(process.env.PORT) || 3000;

  app.set('trust proxy', 1);
  app.use(express.static('public'));

  return {
    app,
    httpServer,
    upload,
    port,
    transport: tlsEnabled ? 'https' : 'http',
  };
};
