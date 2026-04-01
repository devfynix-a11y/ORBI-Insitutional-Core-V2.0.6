import express, { type RequestHandler, type Router } from 'express';

type Deps = {
  authenticate: RequestHandler;
  validate: (schema: any) => RequestHandler;
  upload: any;
  LogicCore: any;
  KYCReviewSchema: any;
  DeviceRegisterSchema: any;
  DeviceTrustSchema: any;
  DocumentUploadSchema: any;
};

const requireAnyRole = (session: any, roles: string[]) => {
  const role = session.role || session.user?.role;
  return roles.includes(role);
};

const parseMaybeJson = (value: any) => {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
};

const parseUploadedBinary = (req: any) => {
  let file: Buffer | undefined;
  let contentType = String(req.headers['content-type'] || 'application/octet-stream');
  let fileName = String(req.headers['x-file-name'] || req.body?.file_name || 'document');

  if (req.file) {
    file = req.file.buffer;
    contentType = req.file.mimetype || contentType;
    fileName = req.file.originalname || fileName;
  } else if (req.body instanceof Buffer) {
    file = req.body;
  } else if (typeof req.body === 'object' && ((req.body as any).image || (req.body as any).file)) {
    const rawData = (req.body as any).image || (req.body as any).file;
    if (typeof rawData === 'string' && rawData.includes('base64,')) {
      const base64Data = rawData.split('base64,')[1];
      file = Buffer.from(base64Data, 'base64');
    }
  }

  return {
    file,
    contentType,
    fileName,
    sizeBytes: file?.length,
  };
};

export const registerSupportOpsRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    validate,
    upload,
    LogicCore,
    KYCReviewSchema,
    DeviceRegisterSchema,
    DeviceTrustSchema,
    DocumentUploadSchema,
  } = deps;

  v1.get('/admin/kyc/requests', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    const status = req.query.status as string;
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);

    try {
      const result = await LogicCore.getKYCRequests(status, limit, offset);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/kyc/review', authenticate, validate(KYCReviewSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const { requestId, decision, reason } = req.body;
      const result = await LogicCore.reviewKYC(requestId, session.sub, decision, reason);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/user/devices', authenticate, validate(DeviceRegisterSchema), async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.registerDevice(session.sub, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/user/devices', authenticate, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.getUserDevices(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.delete('/user/devices/:id', authenticate, async (req, res) => {
    const session = (req as any).session;
    try {
      await LogicCore.removeDevice(session.sub, req.params.id);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/devices', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'IT', 'FRAUD'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);

    try {
      const result = await LogicCore.getAllDevices(limit, offset);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/devices/:id/status', authenticate, validate(DeviceTrustSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'IT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.updateDeviceStatus(req.params.id as string, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post(
    '/user/documents',
    authenticate,
    upload.single('file'),
    express.raw({
      type: [
        'image/png',
        'image/jpeg',
        'image/jpg',
        'image/webp',
        'image/heic',
        'image/heif',
        'application/pdf',
        'application/octet-stream',
      ],
      limit: '20mb',
    }),
    async (req, res) => {
    const session = (req as any).session;
    try {
      const rawBody =
        typeof req.body === 'object' && !(req.body instanceof Buffer) ? req.body : {};
      const documentType = rawBody.document_type;
      if (!documentType) {
        return res.status(400).json({
          success: false,
          error: 'VALIDATION_ERROR',
          message: 'document_type is required.',
        });
      }

      const metadata = parseMaybeJson(rawBody.metadata);
      const parsedUpload = parseUploadedBinary(req);

      let payload: any;
      if (parsedUpload.file) {
        const uploadedUrl = await LogicCore.uploadKYCDocument(
          session.sub,
          parsedUpload.file,
          rawBody.file_name || parsedUpload.fileName,
          rawBody.mime_type || parsedUpload.contentType,
        );

        payload = {
          document_type: documentType,
          file_url: uploadedUrl,
          file_name: rawBody.file_name || parsedUpload.fileName,
          mime_type: rawBody.mime_type || parsedUpload.contentType,
          size_bytes:
            Number(rawBody.size_bytes || 0) > 0
              ? Number(rawBody.size_bytes)
              : parsedUpload.sizeBytes,
          metadata: metadata && typeof metadata === 'object' ? metadata : undefined,
        };
      } else {
        const parsed = DocumentUploadSchema.safeParse({
          ...rawBody,
          metadata,
          size_bytes:
            rawBody.size_bytes !== undefined ? Number(rawBody.size_bytes) : rawBody.size_bytes,
        });

        if (!parsed.success) {
          return res.status(400).json({
            success: false,
            error: 'VALIDATION_ERROR',
            details: parsed.error.flatten(),
          });
        }

        payload = parsed.data;
      }

      const result = await LogicCore.uploadDocument(session.sub, payload);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
    },
  );

  v1.get('/user/documents', authenticate, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.getUserDocuments(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.delete('/user/documents/:id', authenticate, async (req, res) => {
    const session = (req as any).session;
    try {
      await LogicCore.removeDocument(session.sub, req.params.id);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/documents', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);

    try {
      const result = await LogicCore.getAllDocuments(limit, offset);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
};
