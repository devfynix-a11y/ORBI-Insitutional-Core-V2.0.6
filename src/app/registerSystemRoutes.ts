import express from 'express';
import type { Express, RequestHandler } from 'express';
import { registerInternalRoutes, mountInternalRoutes } from '../routes/internal/index.js';
import { registerAdminRoutes, mountAdminRoutes } from '../routes/admin/index.js';

export const registerSystemRoutes = ({
  app,
  authenticate,
}: {
  app: Express;
  authenticate: RequestHandler;
}) => {
  const internal = express.Router();
  registerInternalRoutes(internal);
  mountInternalRoutes(app, internal);

  const admin = express.Router();
  registerAdminRoutes(admin, authenticate as any);
  mountAdminRoutes(app, admin);
};
