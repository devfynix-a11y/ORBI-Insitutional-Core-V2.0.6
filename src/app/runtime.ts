import express from 'express';
import { createServer } from 'http';
import multer from 'multer';

export const createRuntime = () => {
  const app = express();
  const httpServer = createServer(app);
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
  };
};
