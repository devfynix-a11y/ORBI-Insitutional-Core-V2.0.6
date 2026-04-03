export const DEFAULT_MOBILE_APP_ID = process.env.ORBI_MOBILE_APP_ID?.trim() || 'mobile-android';
export const DEFAULT_MOBILE_APP_ORIGIN = process.env.ORBI_MOBILE_ORIGIN?.trim() || 'ORBI_MOBILE_V2026';
export const DEFAULT_DESKTOP_PORTAL_APP_ID =
  process.env.ORBI_CORE_PORTAL_APP_ID?.trim() ||
  process.env.ORBI_DESKTOP_APP_ID?.trim() ||
  'ORBI_NODE_PORTAL_V2026';
export const DEFAULT_DESKTOP_PORTAL_APP_ORIGIN =
  process.env.ORBI_CORE_PORTAL_APP_ORIGIN?.trim() ||
  process.env.ORBI_DESKTOP_APP_ORIGIN?.trim() ||
  'ORBI-NODE-PORTAL-V2026';
export const DEFAULT_INSTITUTIONAL_APP_ID =
  process.env.ORBI_INSTITUTIONAL_APP_ID?.trim() ||
  process.env.ORBI_CORE_PORTAL_APP_ID?.trim() ||
  process.env.ORBI_CORE_APP_ID?.trim() ||
  'ORBI_INSTITUTIONAL_CORE_V2026';
export const DEFAULT_INSTITUTIONAL_APP_ORIGIN =
  process.env.ORBI_INSTITUTIONAL_APP_ORIGIN?.trim() ||
  process.env.ORBI_CORE_PORTAL_APP_ORIGIN?.trim() ||
  process.env.ORBI_CORE_APP_ORIGIN?.trim() ||
  DEFAULT_INSTITUTIONAL_APP_ID;

const LEGACY_INSTITUTIONAL_APP_IDS = [
  'ORBI_NODE_PORTAL_V2026',
  'ORBI_INSTITUTIONAL_CORE_V2026',
  'OBI_INSTITUTIONAL_CORE_V25',
  'DPS_INSTITUTIONAL_CORE_V25',
];

const LEGACY_INSTITUTIONAL_APP_ORIGINS = [
  'ORBI-NODE-PORTAL-V2026',
  'ORBI_INSTITUTIONAL_CORE_V2026',
  'OBI_INSTITUTIONAL_CORE_V25',
  'DPS_INSTITUTIONAL_CORE_V25',
];

const LEGACY_MOBILE_APP_IDS = ['mobile-android', 'mobile-ios'];
const LEGACY_MOBILE_APP_ORIGINS = ['ORBI_MOBILE_V2026', 'OBI_MOBILE_V1'];

function parseIdentityList(...values: Array<string | undefined>): string[] {
  const flattened = values.flatMap((value) =>
    String(value || '')
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean),
  );
  return Array.from(new Set(flattened));
}

export const TRUSTED_INSTITUTIONAL_APP_IDS = parseIdentityList(
  process.env.ORBI_INSTITUTIONAL_APP_ID,
  process.env.ORBI_CORE_PORTAL_APP_ID,
  process.env.ORBI_DESKTOP_APP_ID,
  process.env.ORBI_CORE_APP_ID,
  DEFAULT_DESKTOP_PORTAL_APP_ID,
  ...LEGACY_INSTITUTIONAL_APP_IDS,
);

export const TRUSTED_INSTITUTIONAL_APP_ORIGINS = parseIdentityList(
  process.env.ORBI_INSTITUTIONAL_APP_ORIGIN,
  process.env.ORBI_CORE_PORTAL_APP_ORIGIN,
  process.env.ORBI_DESKTOP_APP_ORIGIN,
  process.env.ORBI_CORE_APP_ORIGIN,
  DEFAULT_DESKTOP_PORTAL_APP_ORIGIN,
  ...LEGACY_INSTITUTIONAL_APP_ORIGINS,
);

export const TRUSTED_MOBILE_APP_IDS = parseIdentityList(
  process.env.ORBI_MOBILE_APP_ID,
  ...LEGACY_MOBILE_APP_IDS,
);

export const TRUSTED_MOBILE_APP_ORIGINS = parseIdentityList(
  process.env.ORBI_MOBILE_ORIGIN,
  ...LEGACY_MOBILE_APP_ORIGINS,
);

export const TRUSTED_APP_IDS = parseIdentityList(
  process.env.ORBI_MOBILE_APP_ID,
  process.env.ORBI_WEB_APP_ID,
  process.env.ORBI_INSTITUTIONAL_APP_ID,
  process.env.ORBI_CORE_PORTAL_APP_ID,
  process.env.ORBI_DESKTOP_APP_ID,
  process.env.ORBI_CORE_APP_ID,
  ...TRUSTED_MOBILE_APP_IDS,
  ...TRUSTED_INSTITUTIONAL_APP_IDS,
);

export const TRUSTED_APP_ORIGINS = parseIdentityList(
  process.env.ORBI_MOBILE_ORIGIN,
  process.env.ORBI_WEB_ORIGIN,
  process.env.ORBI_INSTITUTIONAL_APP_ORIGIN,
  process.env.ORBI_CORE_PORTAL_APP_ORIGIN,
  process.env.ORBI_DESKTOP_APP_ORIGIN,
  process.env.ORBI_CORE_APP_ORIGIN,
  ...TRUSTED_MOBILE_APP_ORIGINS,
  ...TRUSTED_INSTITUTIONAL_APP_ORIGINS,
);

export function isInstitutionalAppIdentity(appId: string, appOrigin: string): boolean {
  return TRUSTED_INSTITUTIONAL_APP_IDS.includes(String(appId || '').trim()) ||
    TRUSTED_INSTITUTIONAL_APP_ORIGINS.includes(String(appOrigin || '').trim());
}

export function isMobileAppIdentity(appId: string, appOrigin: string): boolean {
  return TRUSTED_MOBILE_APP_IDS.includes(String(appId || '').trim()) ||
    TRUSTED_MOBILE_APP_ORIGINS.includes(String(appOrigin || '').trim());
}
