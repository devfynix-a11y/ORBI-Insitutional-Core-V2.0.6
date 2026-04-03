import { Messaging } from './MessagingService.js';
import { gatewayTemplateCatalog, GatewayTemplateSearchInput } from './GatewayTemplateCatalogService.js';
import { messageAudienceService, MessageAudienceFilters, AudienceUser } from './MessageAudienceService.js';
import { TemplateChannel, TemplateLanguage, MessageType } from '../templates/template_types.js';
import { getAdminSupabase } from '../../services/supabaseClient.js';

export type StaffTemplatedSendInput = {
  actorId: string;
  templateName: string;
  variables?: Record<string, any>;
  userIds?: string[];
  filters?: MessageAudienceFilters;
  channel?: TemplateChannel;
  language?: TemplateLanguage;
  messageType?: MessageType;
  category?: 'security' | 'update' | 'promo' | 'info';
  maxRecipients?: number;
};

export type StaffSystemSmsInput = {
  actorId: string;
  body: string;
  userIds?: string[];
  filters?: MessageAudienceFilters;
  category?: 'security' | 'update' | 'promo' | 'info';
  maxRecipients?: number;
};

const normalizeVariables = (variables: Record<string, any> = {}, user: AudienceUser) => ({
  ...variables,
  user: {
    id: user.id,
    full_name: user.full_name || '',
    email: user.email || '',
    phone: user.phone || '',
    nationality: user.nationality || '',
    language: user.language || 'en',
    customer_id: user.customer_id || '',
    created_at: user.created_at || '',
    transaction_count: user.transaction_count,
    total_transaction_amount: user.total_transaction_amount,
    last_transaction_at: user.last_transaction_at || '',
  },
  full_name: user.full_name || '',
  email: user.email || '',
  phone: user.phone || '',
  nationality: user.nationality || '',
  language: user.language || 'en',
  customer_id: user.customer_id || '',
  created_at: user.created_at || '',
  transaction_count: user.transaction_count,
  total_transaction_amount: user.total_transaction_amount,
  last_transaction_at: user.last_transaction_at || '',
});

class StaffMessagingAdminService {
  async searchTemplates(input: GatewayTemplateSearchInput = {}) {
    return gatewayTemplateCatalog.listTemplates(input);
  }

  async previewTemplate(input: { templateName: string; variables?: Record<string, any>; channel?: TemplateChannel; language?: TemplateLanguage; messageType?: MessageType; }) {
    const template = await gatewayTemplateCatalog.getTemplate(input.templateName, {
      channel: input.channel,
      language: input.language,
      messageType: input.messageType,
    });
    if (!template) throw new Error('TEMPLATE_NOT_FOUND');
    const rendered = gatewayTemplateCatalog.renderTemplate(template, input.variables || {});
    return { template, rendered };
  }

  async previewAudience(filters: MessageAudienceFilters = {}) {
    const users = await messageAudienceService.resolve(filters);
    return {
      count: users.length,
      sample: users.slice(0, 25),
    };
  }

  async sendTemplated(input: StaffTemplatedSendInput) {
    const template = await gatewayTemplateCatalog.getTemplate(input.templateName, {
      channel: input.channel,
      language: input.language,
      messageType: input.messageType,
    });
    if (!template) throw new Error('TEMPLATE_NOT_FOUND');

    const recipients = await this.resolveRecipients(input.userIds, input.filters, input.maxRecipients);
    const category = input.category || (template.messageType === 'promotional' ? 'promo' : 'info');
    let delivered = 0;

    for (const recipient of recipients) {
      const mergedVariables = normalizeVariables(input.variables || {}, recipient);
      const rendered = gatewayTemplateCatalog.renderTemplate(template, mergedVariables);
      await Messaging.dispatch(recipient.id, category, rendered.subject || `ORBI ${template.name}`, rendered.body, {
        template: String(template.name),
        variables: mergedVariables,
        eventCode: `STAFF_TEMPLATE_${String(template.name).toUpperCase()}`,
      });
      delivered += 1;
    }

    return {
      delivered,
      audienceCount: recipients.length,
      template,
    };
  }

  async sendSystemCustomSms(input: StaffSystemSmsInput) {
    const recipients = await this.resolveRecipients(input.userIds, input.filters, input.maxRecipients);
    let delivered = 0;
    for (const recipient of recipients) {
      await Messaging.dispatch(recipient.id, input.category || 'info', 'ORBI System Message', input.body, {
        sms: true,
        email: false,
        whatsapp: false,
        push: true,
        systemCustomBypass: true,
        eventCode: 'STAFF_SYSTEM_CUSTOM_SMS',
      });
      delivered += 1;
    }

    return {
      delivered,
      audienceCount: recipients.length,
    };
  }

  private async resolveRecipients(userIds?: string[], filters?: MessageAudienceFilters, maxRecipients?: number) {
    let recipients: AudienceUser[] = [];
    if (Array.isArray(userIds) && userIds.length > 0) {
      const sb = getAdminSupabase();
      if (!sb) throw new Error('DB_OFFLINE');
      const { data, error } = await sb
        .from('users')
        .select('id, full_name, email, phone, nationality, language, registry_type, kyc_status, account_status, app_origin, customer_id, created_at')
        .in('id', userIds);
      if (error) throw new Error(error.message);
      recipients = (data || []).map((user: any) => ({
        ...user,
        transaction_count: 0,
        total_transaction_amount: 0,
        last_transaction_at: null,
      }));
    } else {
      recipients = await messageAudienceService.resolve({ ...(filters || {}), limit: maxRecipients || filters?.limit || 500 });
    }

    const capped = recipients.slice(0, Math.min(Math.max(Number(maxRecipients || recipients.length), 1), 500));
    if (capped.length === 0) throw new Error('AUDIENCE_EMPTY');
    return capped;
  }
}

export const staffMessagingAdminService = new StaffMessagingAdminService();
