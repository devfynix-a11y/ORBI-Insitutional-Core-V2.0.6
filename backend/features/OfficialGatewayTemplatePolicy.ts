import { TemplateName } from '../templates/template_types.js';

export type OfficialMessageCategory = 'security' | 'update' | 'promo' | 'info';

export type OfficialMessageTemplateResolution = {
  templateName?: TemplateName;
  variables: Record<string, any>;
  systemCustomBypass: boolean;
};

class OfficialGatewayTemplatePolicy {
  resolve(input: {
    category: OfficialMessageCategory;
    subject: string;
    body: string;
    refId: string;
    template?: string;
    variables?: Record<string, any>;
    systemCustomBypass?: boolean;
  }): OfficialMessageTemplateResolution {
    const baseVariables = {
      refId: input.refId,
      subject: input.subject,
      body: input.body,
      ...(input.variables || {}),
    };

    if (input.template) {
      return {
        templateName: input.template as TemplateName,
        variables: baseVariables,
        systemCustomBypass: false,
      };
    }

    if (input.systemCustomBypass) {
      return {
        variables: baseVariables,
        systemCustomBypass: true,
      };
    }

    if (input.category === 'security') {
      return {
        templateName: 'Security_Alert_Message',
        variables: baseVariables,
        systemCustomBypass: false,
      };
    }

    if (input.category === 'promo') {
      return {
        templateName: 'Promo_Message',
        variables: {
          body: input.body,
          ...(input.variables || {}),
        },
        systemCustomBypass: false,
      };
    }

    return {
      templateName: 'Transactional_Message',
      variables: {
        body: input.body,
        refId: input.refId,
        ...(input.variables || {}),
      },
      systemCustomBypass: false,
    };
  }
}

export const officialGatewayTemplatePolicy = new OfficialGatewayTemplatePolicy();
