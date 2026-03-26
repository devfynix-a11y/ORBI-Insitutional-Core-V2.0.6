import { getAdminSupabase, getSupabase } from '../supabaseClient.js';
import { Audit } from '../security/audit.js';
import { RedisClusterFactory } from '../infrastructure/RedisClusterFactory.js';
import {
  PlatformFeeConfig,
  PlatformFeeComputation,
  PlatformFeeFlowCode,
  RailType,
} from '../../types.js';

type PlatformFeeFilters = {
  flowCode?: string;
  status?: string;
  providerId?: string;
  currency?: string;
  countryCode?: string;
  rail?: string;
};

type FeeResolutionInput = {
  flowCode: PlatformFeeFlowCode | string;
  amount: number;
  currency: string;
  providerId?: string;
  countryCode?: string;
  rail?: RailType | string;
  channel?: string;
  direction?: string;
  operationType?: string;
  transactionType?: string;
  metadata?: Record<string, any>;
};

const LEGACY_DEFAULTS: Record<string, Partial<PlatformFeeConfig>> = {
  CORE_TRANSACTION: { percentage_rate: 0.01, tax_rate: 0.05, stamp_duty_fixed: 1, gov_fee_rate: 0 },
  EXTERNAL_PAYMENT: { percentage_rate: 0.01, tax_rate: 0.05, stamp_duty_fixed: 1, gov_fee_rate: 0.005 },
  WITHDRAWAL: { percentage_rate: 0.01, tax_rate: 0.05, stamp_duty_fixed: 1, gov_fee_rate: 0.005 },
  EXTERNAL_TO_INTERNAL: { percentage_rate: 0, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  INTERNAL_TO_EXTERNAL: { percentage_rate: 0, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  EXTERNAL_TO_EXTERNAL: { percentage_rate: 0, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  CARD_SETTLEMENT: { percentage_rate: 0.01, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  GATEWAY_SETTLEMENT: { percentage_rate: 0.01, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  FX_CONVERSION: { percentage_rate: 0.005, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  TENANT_SETTLEMENT_PAYOUT: { percentage_rate: 0.005, fixed_amount: 500, minimum_fee: 500, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  MERCHANT_PAYMENT: { percentage_rate: 0.01, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  AGENT_CASH_DEPOSIT: { percentage_rate: 0, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  AGENT_CASH_WITHDRAWAL: { percentage_rate: 0.005, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  AGENT_REFERRAL_COMMISSION: { percentage_rate: 0.005, fixed_amount: 0, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  AGENT_CASH_COMMISSION: { percentage_rate: 0.003, fixed_amount: 0, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
  SYSTEM_OPERATION: { percentage_rate: 0, tax_rate: 0, stamp_duty_fixed: 0, gov_fee_rate: 0 },
};

export class PlatformFeeService {
  private cache = new Map<string, { expiresAt: number; data: PlatformFeeConfig[] }>();
  private cacheTtlMs = 60 * 1000;

  async listConfigs(filters?: PlatformFeeFilters) {
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) throw new Error('DB_OFFLINE');

    const cacheKey = this.buildCacheKey(filters);
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.data;
    }
    const redis = RedisClusterFactory.getClient('monitor');
    if (redis && process.env.ORBI_DISABLE_REDIS_CACHE !== 'true') {
      try {
        const cachedRaw = await redis.get(`platform_fees:${cacheKey}`);
        if (cachedRaw) {
          const parsed = JSON.parse(String(cachedRaw));
          this.cache.set(cacheKey, { expiresAt: Date.now() + this.cacheTtlMs, data: parsed });
          return parsed;
        }
      } catch (e) {
        // Redis is optional; fall back to DB.
      }
    }

    let query = sb
      .from('platform_fee_configs')
      .select('*, financial_partners(id, name, type, provider_metadata)')
      .order('flow_code', { ascending: true })
      .order('priority', { ascending: true })
      .order('updated_at', { ascending: false });

    if (filters?.flowCode) query = query.eq('flow_code', String(filters.flowCode).trim().toUpperCase());
    if (filters?.status) query = query.eq('status', String(filters.status).trim().toUpperCase());
    if (filters?.providerId) query = query.eq('provider_id', filters.providerId);
    if (filters?.currency) query = query.eq('currency', String(filters.currency).trim().toUpperCase());
    if (filters?.countryCode) query = query.eq('country_code', String(filters.countryCode).trim().toUpperCase());
    if (filters?.rail) query = query.eq('rail', String(filters.rail).trim().toUpperCase());

    const { data, error } = await query;
    if (error) throw new Error(error.message);
    const rows = data || [];
    this.cache.set(cacheKey, { expiresAt: Date.now() + this.cacheTtlMs, data: rows });
    if (redis && process.env.ORBI_DISABLE_REDIS_CACHE !== 'true') {
      try {
        await redis.set(`platform_fees:${cacheKey}`, JSON.stringify(rows), 'EX', Math.ceil(this.cacheTtlMs / 1000));
      } catch (e) {
        // Ignore Redis write errors.
      }
    }
    return rows;
  }

  async upsertConfig(payload: any, actorId: string, configId?: string) {
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) throw new Error('DB_OFFLINE');

    const existing = configId
      ? await sb.from('platform_fee_configs').select('*').eq('id', configId).maybeSingle()
      : { data: null, error: null };

    if (existing.error) throw new Error(existing.error.message);
    if (configId && !existing.data) throw new Error('PLATFORM_FEE_CONFIG_NOT_FOUND');

    const current = existing.data || {};
    const now = new Date().toISOString();
    const normalized = {
      name: String(payload.name ?? current.name ?? '').trim(),
      flow_code: String(payload.flowCode ?? payload.flow_code ?? current.flow_code ?? '').trim().toUpperCase(),
      transaction_type: this.normalizeNullableText(payload.transactionType ?? payload.transaction_type ?? current.transaction_type),
      operation_type: this.normalizeNullableText(payload.operationType ?? payload.operation_type ?? current.operation_type),
      direction: this.normalizeNullableText(payload.direction ?? current.direction),
      rail: this.normalizeNullableText(payload.rail ?? current.rail),
      channel: this.normalizeNullableText(payload.channel ?? current.channel),
      provider_id: payload.providerId ?? payload.provider_id ?? current.provider_id ?? null,
      currency: this.normalizeNullableText(payload.currency ?? current.currency),
      country_code: this.normalizeNullableText(payload.countryCode ?? payload.country_code ?? current.country_code),
      percentage_rate: this.parseRate(payload.percentageRate ?? payload.percentage_rate ?? current.percentage_rate),
      fixed_amount: this.parseAmount(payload.fixedAmount ?? payload.fixed_amount ?? current.fixed_amount),
      minimum_fee: this.parseAmount(payload.minimumFee ?? payload.minimum_fee ?? current.minimum_fee),
      maximum_fee: this.parseNullableAmount(payload.maximumFee ?? payload.maximum_fee ?? current.maximum_fee),
      tax_rate: this.parseRate(payload.taxRate ?? payload.tax_rate ?? current.tax_rate),
      gov_fee_rate: this.parseRate(payload.govFeeRate ?? payload.gov_fee_rate ?? current.gov_fee_rate),
      stamp_duty_fixed: this.parseAmount(payload.stampDutyFixed ?? payload.stamp_duty_fixed ?? current.stamp_duty_fixed),
      priority: this.parseInteger(payload.priority ?? current.priority ?? 100),
      status: String(payload.status ?? current.status ?? 'ACTIVE').trim().toUpperCase(),
      metadata: payload.metadata ?? current.metadata ?? {},
      updated_at: now,
    };

    if (!normalized.name || !normalized.flow_code) {
      throw new Error('INVALID_PLATFORM_FEE_CONFIG');
    }

    const query = configId
      ? sb.from('platform_fee_configs').update(normalized).eq('id', configId).select('*').single()
      : sb.from('platform_fee_configs').insert({ ...normalized, created_at: now }).select('*').single();

    const { data, error } = await query;
    if (error) throw new Error(error.message);

    this.cache.clear();
    // Redis cache is short-lived; allow natural expiry for now.

    await Audit.log('ADMIN', actorId, configId ? 'PLATFORM_FEE_CONFIG_UPDATED' : 'PLATFORM_FEE_CONFIG_CREATED', {
      configId: data.id,
      flowCode: data.flow_code,
      currency: data.currency,
      providerId: data.provider_id,
    });

    return data;
  }

  async resolveFee(input: FeeResolutionInput): Promise<PlatformFeeComputation> {
    const amount = this.parseAmount(input.amount);
    const flowCode = String(input.flowCode || '').trim().toUpperCase();
    const currency = String(input.currency || '').trim().toUpperCase();
    if (!currency) {
      throw new Error(`FEE_CURRENCY_REQUIRED:${flowCode}`);
    }

    const activeConfigs = await this.listConfigs({
      flowCode,
      status: 'ACTIVE',
      providerId: input.providerId,
      currency,
      countryCode: input.countryCode,
      rail: input.rail,
    });

    const config = this.selectBestConfig(activeConfigs as PlatformFeeConfig[], input) || this.buildLegacyFallback(flowCode, currency);
    return this.computeFromConfig(config, amount, currency, input);
  }

  private buildCacheKey(filters?: PlatformFeeFilters) {
    const normalized = {
      flowCode: String(filters?.flowCode || '').trim().toUpperCase(),
      status: String(filters?.status || '').trim().toUpperCase(),
      providerId: String(filters?.providerId || ''),
      currency: String(filters?.currency || '').trim().toUpperCase(),
      countryCode: String(filters?.countryCode || '').trim().toUpperCase(),
      rail: String(filters?.rail || '').trim().toUpperCase(),
    };
    return JSON.stringify(normalized);
  }

  private selectBestConfig(configs: PlatformFeeConfig[], input: FeeResolutionInput) {
    const normalized = {
      providerId: input.providerId || null,
      currency: this.normalizeNullableText(input.currency),
      countryCode: this.normalizeNullableText(input.countryCode),
      rail: this.normalizeNullableText(input.rail),
      channel: this.normalizeNullableText(input.channel),
      direction: this.normalizeNullableText(input.direction),
      operationType: this.normalizeNullableText(input.operationType),
      transactionType: this.normalizeNullableText(input.transactionType),
    };

    return configs
      .filter((config) => this.matchesOptionalField(config.provider_id, normalized.providerId))
      .filter((config) => this.matchesOptionalField(config.currency, normalized.currency))
      .filter((config) => this.matchesOptionalField(config.country_code, normalized.countryCode))
      .filter((config) => this.matchesOptionalField(config.rail, normalized.rail))
      .filter((config) => this.matchesOptionalField(config.channel, normalized.channel))
      .filter((config) => this.matchesOptionalField(config.direction, normalized.direction))
      .filter((config) => this.matchesOptionalField(config.operation_type, normalized.operationType))
      .filter((config) => this.matchesOptionalField(config.transaction_type, normalized.transactionType))
      .sort((a, b) => {
        const specificityDelta = this.specificityScore(b) - this.specificityScore(a);
        if (specificityDelta !== 0) return specificityDelta;
        return Number(a.priority || 100) - Number(b.priority || 100);
      })[0];
  }

  private computeFromConfig(
    config: Partial<PlatformFeeConfig>,
    amount: number,
    currency: string,
    input: FeeResolutionInput,
  ): PlatformFeeComputation {
    const percentageRate = this.parseRate(config.percentage_rate);
    const fixedAmount = this.parseAmount(config.fixed_amount);
    const minimumFee = this.parseAmount(config.minimum_fee);
    const maximumFee = this.parseNullableAmount(config.maximum_fee);
    const taxRate = this.parseRate(config.tax_rate);
    const govFeeRate = this.parseRate(config.gov_fee_rate);
    const stampDutyFixed = this.parseAmount(config.stamp_duty_fixed);

    const percentageFee = this.roundAmount(amount * percentageRate);
    let serviceFee = this.roundAmount(percentageFee + fixedAmount);
    if (minimumFee > 0) serviceFee = Math.max(serviceFee, minimumFee);
    if (maximumFee !== null) serviceFee = Math.min(serviceFee, maximumFee);

    const taxAmount = this.roundAmount(amount * taxRate);
    const govFeeAmount = this.roundAmount(amount * govFeeRate);
    const totalFee = this.roundAmount(serviceFee + taxAmount + govFeeAmount + stampDutyFixed);

    return {
      flowCode: String(config.flow_code || input.flowCode).trim().toUpperCase(),
      configId: config.id || null,
      configName: config.name || 'LEGACY_FALLBACK',
      currency,
      amount,
      percentageRate,
      fixedAmount,
      minimumFee,
      maximumFee,
      taxRate,
      govFeeRate,
      stampDutyFixed,
      percentageFee,
      serviceFee,
      taxAmount,
      govFeeAmount,
      totalFee,
      netAmount: this.roundAmount(amount - totalFee),
      metadata: {
        ...(config.metadata || {}),
        input_metadata: input.metadata || {},
        provider_id: input.providerId || null,
      },
    };
  }

  private buildLegacyFallback(flowCode: string, currency: string): Partial<PlatformFeeConfig> {
    const fallback = LEGACY_DEFAULTS[flowCode] || LEGACY_DEFAULTS.CORE_TRANSACTION;
    return {
      id: null as any,
      name: `LEGACY_${flowCode}`,
      flow_code: flowCode,
      currency,
      percentage_rate: fallback.percentage_rate ?? 0,
      fixed_amount: fallback.fixed_amount ?? 0,
      minimum_fee: fallback.minimum_fee ?? 0,
      maximum_fee: fallback.maximum_fee ?? null,
      tax_rate: fallback.tax_rate ?? 0,
      gov_fee_rate: fallback.gov_fee_rate ?? 0,
      stamp_duty_fixed: fallback.stamp_duty_fixed ?? 0,
      priority: 9999,
      status: 'ACTIVE',
      metadata: { fallback: true },
    };
  }

  private matchesOptionalField(configValue: any, inputValue: any) {
    if (configValue === null || configValue === undefined || String(configValue).trim() === '') {
      return true;
    }
    if (inputValue === null || inputValue === undefined || String(inputValue).trim() === '') {
      return false;
    }
    return String(configValue).trim().toUpperCase() === String(inputValue).trim().toUpperCase();
  }

  private specificityScore(config: Partial<PlatformFeeConfig>) {
    return [
      config.provider_id,
      config.currency,
      config.country_code,
      config.rail,
      config.channel,
      config.direction,
      config.operation_type,
      config.transaction_type,
    ].filter((value) => value !== null && value !== undefined && String(value).trim() !== '').length;
  }

  private normalizeNullableText(value: any) {
    const text = String(value ?? '').trim();
    return text ? text.toUpperCase() : null;
  }

  private parseRate(value: any) {
    const parsed = Number(value ?? 0);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  private parseAmount(value: any) {
    const parsed = Number(value ?? 0);
    if (!Number.isFinite(parsed)) return 0;
    return this.roundAmount(parsed);
  }

  private parseNullableAmount(value: any) {
    if (value === null || value === undefined || value === '') return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? this.roundAmount(parsed) : null;
  }

  private parseInteger(value: any) {
    const parsed = Number.parseInt(String(value ?? 100), 10);
    return Number.isFinite(parsed) ? parsed : 100;
  }

  private roundAmount(value: number) {
    return Math.round(value * 100) / 100;
  }
}

export const platformFeeService = new PlatformFeeService();
