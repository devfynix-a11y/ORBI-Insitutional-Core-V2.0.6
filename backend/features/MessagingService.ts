
import { UserMessage, UserProfile, Wallet } from '../../types.js';
import { getSupabase, getAdminSupabase } from '../../services/supabaseClient.js';
import { UUID } from '../../services/utils.js';
import { Storage, STORAGE_KEYS } from '../storage.js';
import { GoogleGenAI } from "@google/genai";
import { DataVault } from '../security/encryption.js';
import { DataProtection } from '../security/DataProtection.js';
import { orbiGatewayService } from '../infrastructure/orbiGatewayService.js';
import { firebasePushService } from '../infrastructure/firebasePushService.js';
import parsePhoneNumber from 'libphonenumber-js';

import { SocketRegistry } from '../infrastructure/SocketRegistry.js';

import { TemplateName, TemplatePayloads } from '../templates/template_types.js';
import { officialGatewayTemplatePolicy } from './OfficialGatewayTemplatePolicy.js';

/**
 * NEXUS MESSAGING & NOTIFICATION NODE (V5.1)
 * -----------------------------------------
 * Orchestrates direct-to-user alerts and AI-synthesized system notifications.
 */
class MessagingService {
    private readonly profileCache = new Map<string, { value: any; expiresAt: number }>();
    private readonly profileInflight = new Map<string, Promise<any>>();
    private readonly PROFILE_CACHE_TTL_MS = 30_000;

    private async getUserProfile(userId: string): Promise<any> {
        const now = Date.now();
        const cached = this.profileCache.get(userId);
        if (cached && cached.expiresAt > now) {
            return cached.value;
        }

        const inflight = this.profileInflight.get(userId);
        if (inflight) {
            return inflight;
        }

        const loadPromise = this.loadUserProfile(userId);
        this.profileInflight.set(userId, loadPromise);
        try {
            const profile = await loadPromise;
            this.profileCache.set(userId, {
                value: profile,
                expiresAt: now + this.PROFILE_CACHE_TTL_MS,
            });
            return profile;
        } finally {
            this.profileInflight.delete(userId);
        }
    }

    private async loadUserProfile(userId: string): Promise<any> {
        const sb = getAdminSupabase();
        if (sb) {
            let { data: profile } = await sb.from('users')
                .select('language, notif_push, notif_email, notif_security, notif_financial, notif_budget, notif_marketing, phone, nationality, email, fcm_token, id_type')
                .eq('id', userId)
                .maybeSingle();
                
            if (!profile) {
                const { data: staffProfile } = await sb.from('staff')
                    .select('language, notif_push, notif_email, notif_security, notif_financial, notif_budget, notif_marketing, phone, nationality, email, fcm_token, id_type')
                    .eq('id', userId)
                    .maybeSingle();
                profile = staffProfile;
            }

            const profileData: any = profile || {};
            
            // Fallback to Auth if phone is missing
            let phone = profileData.phone;
            if (!phone && userId && userId !== 'system') {
                const { data: authData } = await sb.auth.admin.getUserById(userId);
                phone = authData.user?.phone || authData.user?.user_metadata?.phone || '';
            }

            return {
                language: profileData.language || 'en',
                notif_push: profileData.notif_push ?? true,
                notif_email: profileData.notif_email ?? true,
                notif_security: profileData.notif_security ?? true,
                notif_financial: profileData.notif_financial ?? true,
                notif_budget: profileData.notif_budget ?? true,
                notif_marketing: profileData.notif_marketing ?? false,
                phone: phone,
                nationality: profileData.nationality || 'Tanzania',
                email: profileData.email,
                fcm_token: profileData.fcm_token,
                id_type: profileData.id_type
            };
        }
        return {
            language: 'en',
            notif_push: true,
            notif_email: true,
            notif_security: true,
            notif_financial: true,
            notif_budget: true,
            notif_marketing: false,
            nationality: 'Tanzania'
        };
    }

    public async sendWelcomeMessage(user: any, wallets: Wallet[]) {
        const orbiWallet = wallets.find(w => w.name === 'Orbi') || wallets[0];
        const accountId = orbiWallet?.accountNumber || user.customer_id || 'Pending';
        const profile = await this.getUserProfile(user.id);
        const language = profile.language;
        
        let userFullName = user.user_metadata?.full_name;
        if (!userFullName) {
            const sb = getAdminSupabase();
            if (sb) {
                let { data: profile } = await sb.from('users').select('full_name').eq('id', user.id).maybeSingle();
                if (!profile) {
                    const { data: staffProfile } = await sb.from('staff').select('full_name').eq('id', user.id).maybeSingle();
                    profile = staffProfile;
                }
                userFullName = profile?.full_name;
            }
        }
        userFullName = userFullName || (language === 'sw' ? 'Mteja' : 'Customer');
        
        const translations = {
            en: {
                subject: "Welcome to Orbi",
                body: `Hello ${userFullName},

Welcome to Orbi. We are pleased to inform you that your account is now active and ready for use.

**Account Details:**
- **Account ID:** ${accountId}
- **Registered Email:** ${user.email}

Your Orbi and PaySafe accounts have been successfully configured. You may now begin managing your assets through our secure platform.

Should you require any assistance, our support team is available to help:
- **Phone:** [+255 764 258 114](tel:+255764258114)
- **Email:** [auth.orbi@gmail.com](mailto:auth.orbi@gmail.com)

Thank you for choosing Orbi.

Best regards,

**Daniel Z. Gibai**
CEO, ORBI`
            },
            sw: {
                subject: "Karibu Orbi",
                body: `Habari ${userFullName},

Karibu Orbi. Tunafurahi kukujulisha kuwa akaunti yako sasa imewashwa na iko tayari kukutumia.

**Maelezo ya Akaunti:**
- **ID ya Akaunti:** ${accountId}
- **Barua Pepe:** ${user.email}

Akaunti zako za Orbi na PaySafe zimesanidiwa kwa mafanikio. Sasa unaweza kuanza kusimamia mali zako kupitia jukwaa letu salama.

Ikiwa unahitaji msaada wowote, timu yetu ya msaada iko tayari kukusaidia:
- **Simu:** [+255 764 258 114](tel:+255764258114)
- **Barua Pepe:** [auth.orbi@gmail.com](mailto:auth.orbi@gmail.com)

Asante kwa kuichagua Orbi.

Kila la heri,

**Daniel Z. Gibai**
CEO, ORBI`
            }
        };

        const t = translations[language as 'en' | 'sw'] || translations.en;
        const subject = t.subject;
        const body = t.body;

        // 1. Dispatch In-App Notification (Push via Socket)
        await this.dispatch(user.id, 'info', subject, body, {
            sms: true,
            email: true,
            template: 'Welcome_Message',
            variables: { name: userFullName }
        });
    }

    public async dispatch(
        userId: string, 
        category: 'security' | 'update' | 'promo' | 'info',
        subject: string, 
        body: string,
        options: {
            sms?: boolean,
            email?: boolean,
            push?: boolean,
            whatsapp?: boolean,
            template?: string,
            eventCode?: string,
            variables?: Record<string, any>,
            systemCustomBypass?: boolean,
        } = {}
    ): Promise<UserMessage | null> {
        const sb = getAdminSupabase();
        
        // Check user profile and preferences before dispatching
        const profile = await this.getUserProfile(userId);
        
        const isAllowed = (cat: string) => {
            if (cat === 'security') return profile.notif_security;
            if (cat === 'promo') return profile.notif_marketing;
            if (cat === 'update') return profile.notif_financial;
            if (cat === 'info') return profile.notif_financial || profile.notif_budget;
            return true;
        };

        if (!isAllowed(category)) {
            console.info(`[Messaging] Skipping notification for ${userId} due to preference settings for category: ${category}`);
            return null;
        }

        const pushAllowed = profile.notif_push !== false;
        const emailAllowed = profile.notif_email !== false;
        if (!pushAllowed) options.push = false;
        if (!emailAllowed) options.email = false;

        const id = UUID.generate();
        const refId = id.substring(0, 8).toUpperCase();
        const isTransactional = ['security', 'update', 'info'].includes(category);
        const templatePlan = officialGatewayTemplatePolicy.resolve({
            category,
            subject,
            body,
            refId,
            template: options.template,
            variables: options.variables,
            systemCustomBypass: options.systemCustomBypass,
        });

        let displaySubject = subject;
        let displayBody = body;

        if (isTransactional && !body.includes('Ref:') && !body.includes('Kumb:')) {
            displayBody = `Ref: ${refId}. ${body}`;
        }
        
        // Encrypt sensitive content before persistence
        const [encSubject, encBody] = await Promise.all([
            DataProtection.encryptMessageContent(displaySubject, { field: 'subject' }),
            DataProtection.encryptMessageContent(displayBody, { field: 'body' })
        ]);

        const msg: UserMessage = {
            id, 
            user_id: userId, 
            subject: encSubject as any, 
            body: encBody as any, 
            category, 
            is_read: false, 
            created_at: new Date().toISOString()
        };

        // 0. Real-Time Nexus Push (Decrypted for immediate display)
        console.log(`[Messaging] Attempting to send Socket notification to ${userId}`);
        const socketSent = SocketRegistry.send(userId, {
            type: 'NOTIFICATION',
            payload: {
                id,
                refId,
                category,
                template_name: options.template,
                event_code: options.eventCode,
                subject: displaySubject, // Send plain text for display
                body: displayBody,       // Send plain text for display
                timestamp: msg.created_at
            }
        });
        console.log(`[Messaging] Socket notification sent result: ${socketSent} for user ${userId}`);

        // 1. Cloud Sync
        if (sb) {
            try { 
                await sb.from('user_messages').insert(msg); 
                console.log(`[Messaging] Cloud sync successful for message ${id}`);
            } catch (e) {
                console.error("[Messaging] Cloud push fault.", e);
            }
        }

        // 2. Multi-Channel Escalation
        const isTanzania = profile.nationality?.toLowerCase().includes('tanzania') || 
                           profile.nationality?.toLowerCase().includes('tz') || 
                           profile.phone?.startsWith('+255') ||
                           profile.id_type === 'NIDA';
        const language = profile.language || 'en';
        
        // Add refId to variables for templates
        const vars = { 
            refId,
            ...templatePlan.variables,
            ...(options.variables || {}),
            subject: displaySubject,
            body: displayBody,
        };

        let formattedPhone = profile.phone;
        if (profile.phone) {
            try {
                const parsed = parsePhoneNumber(profile.phone, (profile.country as any) || 'TZ');
                formattedPhone = parsed ? parsed.format('E.164') : (profile.phone.startsWith('+') ? profile.phone : '+' + profile.phone.replace(/\s/g, ''));
            } catch (e) {
                formattedPhone = profile.phone.startsWith('+') ? profile.phone : '+' + profile.phone.replace(/\s/g, '');
            }
        }

        // User Request: if the user is from Tanzania prefer SMS, otherwise sent to email or whatsapp
        if (isTanzania && profile.phone) {
            options.sms = true;
            options.email = false;
            options.whatsapp = false;
        } else if (profile.email) {
            options.email = true;
            options.sms = false;
            options.whatsapp = options.whatsapp ?? false;
        } else if (profile.phone) {
            // Non-Tanzania with phone but no email -> WhatsApp
            options.whatsapp = true;
            options.sms = false;
            options.email = false;
        }

        if (pushAllowed && (isTanzania || profile.fcm_token)) {
            options.push = options.push ?? true;
        }

        // Try Push Notification
        if (options.push && pushAllowed && profile.fcm_token) {
            await firebasePushService.send({
                token: profile.fcm_token,
                title: displaySubject,
                body: displayBody,
                data: {
                    category,
                    messageId: id,
                    refId,
                    ...(options.template ? { templateName: options.template } : {}),
                    ...(options.eventCode ? { eventCode: options.eventCode } : {}),
                },
                requestId: id,
            });
        }

        // Try SMS
        if (options.sms && profile.phone) {
            if (templatePlan.templateName) {
                await orbiGatewayService.sendTemplate(templatePlan.templateName as TemplateName, formattedPhone, vars as any, { 
                    language, 
                    messageType: category === 'promo' ? 'promotional' : 'transactional',
                    channel: 'sms',
                    fcmToken: profile.fcm_token,
                    requestId: id
                });
            } else if (templatePlan.systemCustomBypass) {
                await orbiGatewayService.sendSms(formattedPhone, `${subject}: ${body}`, language, undefined, undefined, id);
            }
        }

        // Try Email (with fallback to SMS if requested)
        if (options.email && emailAllowed && profile.email) {
            let emailSent = false;
            if (templatePlan.templateName) {
                emailSent = await orbiGatewayService.sendTemplate(templatePlan.templateName as TemplateName, profile.email, vars as any, { 
                    language, 
                    messageType: category === 'promo' ? 'promotional' : 'transactional',
                    channel: 'email',
                    fcmToken: profile.fcm_token,
                    requestId: id
                });
            }
        }

        // Try WhatsApp
        if (options.whatsapp && profile.phone) {
            if (templatePlan.templateName) {
                await orbiGatewayService.sendTemplate(templatePlan.templateName as TemplateName, formattedPhone, vars as any, { 
                    language, 
                    messageType: category === 'promo' ? 'promotional' : 'transactional',
                    channel: 'whatsapp',
                    fcmToken: profile.fcm_token,
                    requestId: id
                });
            } else if (templatePlan.systemCustomBypass) {
                // Fallback to SMS if no template, as WhatsApp usually requires templates for business-initiated messages
                await orbiGatewayService.sendSms(formattedPhone, `${subject}: ${body}`, language, undefined, undefined, id);
            }
        }

        // 3. Local Volatile Cache for Instant Retrieval
        const localMsgs = Storage.getFromDB<UserMessage>('orbi_messages') || [];
        localMsgs.unshift(msg);
        Storage.saveToDB('orbi_messages', localMsgs.slice(0, 50));

        console.info(`[Messaging] Node Signal Dispatched to ${userId}: ${subject}`);
        return msg;
    }

    public async dispatchServiceActivity(
        userId: string,
        event:
            | 'MERCHANT_PAYMENT_PENDING'
            | 'MERCHANT_PAYMENT_COMPLETED'
            | 'MERCHANT_PAYMENT_FAILED'
            | 'MERCHANT_CUSTOMER_PAYMENT_PENDING'
            | 'MERCHANT_CUSTOMER_PAYMENT_COMPLETED'
            | 'MERCHANT_CUSTOMER_PAYMENT_FAILED'
            | 'AGENT_CASH_PENDING'
            | 'AGENT_CASH_COMPLETED'
            | 'AGENT_CASH_FAILED'
            | 'AGENT_CUSTOMER_CASH_PENDING'
            | 'AGENT_CUSTOMER_CASH_COMPLETED'
            | 'AGENT_CUSTOMER_CASH_FAILED'
            | 'AGENT_COMMISSION_PAID'
            | 'SERVICE_CUSTOMER_REGISTERED'
            | 'SERVICE_CUSTOMER_ONBOARDED'
            | 'SERVICE_ACCESS_APPROVED',
        context: Record<string, any> = {},
        category: 'update' | 'info' | 'security' = 'update',
    ) {
        const profile = await this.getUserProfile(userId);
        const language = profile.language === 'sw' ? 'sw' : 'en';
        const currency = context.currency || 'TZS';
        const numericAmount = context.amount != null ? Number(context.amount) : null;
        const amount = numericAmount != null ? `${numericAmount.toLocaleString(language === 'sw' ? 'sw-TZ' : 'en-US')} ${currency}` : null;
        const actorLabel = context.actorLabel || (language === 'sw' ? 'huduma yako ya ORBI' : 'your ORBI service desk');
        const customerLabel = context.customerName || context.customerId || (language === 'sw' ? 'mteja' : 'customer');
        const direction = String(context.direction || '').toLowerCase();

        const translations = {
            en: {
                MERCHANT_PAYMENT_PENDING: {
                    subject: 'Merchant payment received',
                    body: `A merchant payment of ${amount || currency} is being processed in ${actorLabel}.`,
                },
                MERCHANT_PAYMENT_COMPLETED: {
                    subject: 'Merchant payment completed',
                    body: `A merchant payment of ${amount || currency} has settled successfully in ${actorLabel}.`,
                },
                MERCHANT_PAYMENT_FAILED: {
                    subject: 'Merchant payment update',
                    body: `A merchant payment in ${actorLabel} did not complete. Review the latest transaction activity for details.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_PENDING: {
                    subject: 'Merchant payment is processing',
                    body: `Your payment of ${amount || currency} is being processed through ${actorLabel}.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_COMPLETED: {
                    subject: 'Merchant payment completed',
                    body: `Your payment of ${amount || currency} through ${actorLabel} completed successfully.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_FAILED: {
                    subject: 'Merchant payment update',
                    body: `Your payment through ${actorLabel} did not complete. Review your latest activity for details.`,
                },
                AGENT_CASH_PENDING: {
                    subject: 'Agent cash request received',
                    body: `A ${direction || 'cash'} request of ${amount || currency} is being processed in ${actorLabel}.`,
                },
                AGENT_CASH_COMPLETED: {
                    subject: 'Agent cash request completed',
                    body: `A ${direction || 'cash'} request of ${amount || currency} has completed successfully in ${actorLabel}.`,
                },
                AGENT_CASH_FAILED: {
                    subject: 'Agent cash request update',
                    body: `A ${direction || 'cash'} request in ${actorLabel} did not complete. Review the latest activity for details.`,
                },
                AGENT_CUSTOMER_CASH_PENDING: {
                    subject: 'Cash service is processing',
                    body: `Your ${direction || 'cash'} request of ${amount || currency} is being processed through ${actorLabel}.`,
                },
                AGENT_CUSTOMER_CASH_COMPLETED: {
                    subject: 'Cash service completed',
                    body: `Your ${direction || 'cash'} request of ${amount || currency} through ${actorLabel} completed successfully.`,
                },
                AGENT_CUSTOMER_CASH_FAILED: {
                    subject: 'Cash service update',
                    body: `Your ${direction || 'cash'} request through ${actorLabel} did not complete. Review your latest activity for details.`,
                },
                AGENT_COMMISSION_PAID: {
                    subject: 'Agent commission paid',
                    body: `A commission of ${amount || currency} was credited to your ORBI agent account.`,
                },
                SERVICE_CUSTOMER_REGISTERED: {
                    subject: 'Customer added successfully',
                    body: `${customerLabel} was added through ${actorLabel} and is now linked to your service activity.`,
                },
                SERVICE_CUSTOMER_ONBOARDED: {
                    subject: 'Your ORBI account is ready',
                    body: `Your ORBI account was created successfully and linked to ${actorLabel}.`,
                },
                SERVICE_ACCESS_APPROVED: {
                    subject: 'Service access approved',
                    body: `Your ORBI access has been updated. ${actorLabel} is now available on your account.`,
                },
            },
            sw: {
                MERCHANT_PAYMENT_PENDING: {
                    subject: 'Malipo ya merchant yamepokelewa',
                    body: `Malipo ya merchant ya ${amount || currency} yanachakatwa kwenye ${actorLabel}.`,
                },
                MERCHANT_PAYMENT_COMPLETED: {
                    subject: 'Malipo ya merchant yamekamilika',
                    body: `Malipo ya merchant ya ${amount || currency} yamekamilika kwa mafanikio kwenye ${actorLabel}.`,
                },
                MERCHANT_PAYMENT_FAILED: {
                    subject: 'Taarifa ya malipo ya merchant',
                    body: `Malipo ya merchant kwenye ${actorLabel} hayajakamilika. Angalia shughuli zako za karibuni kwa maelezo.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_PENDING: {
                    subject: 'Malipo ya merchant yanachakatwa',
                    body: `Malipo yako ya ${amount || currency} kupitia ${actorLabel} yanachakatwa.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_COMPLETED: {
                    subject: 'Malipo ya merchant yamekamilika',
                    body: `Malipo yako ya ${amount || currency} kupitia ${actorLabel} yamekamilika kwa mafanikio.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_FAILED: {
                    subject: 'Taarifa ya malipo ya merchant',
                    body: `Malipo yako kupitia ${actorLabel} hayajakamilika. Angalia shughuli zako za karibuni kwa maelezo.`,
                },
                AGENT_CASH_PENDING: {
                    subject: 'Ombi la fedha la agent limepokelewa',
                    body: `Ombi la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} la ${amount || currency} linachakatwa kwenye ${actorLabel}.`,
                },
                AGENT_CASH_COMPLETED: {
                    subject: 'Ombi la fedha la agent limekamilika',
                    body: `Ombi la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} la ${amount || currency} limekamilika kwa mafanikio kwenye ${actorLabel}.`,
                },
                AGENT_CASH_FAILED: {
                    subject: 'Taarifa ya fedha ya agent',
                    body: `Ombi la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} kwenye ${actorLabel} halijakamilika. Angalia shughuli zako za karibuni kwa maelezo.`,
                },
                AGENT_CUSTOMER_CASH_PENDING: {
                    subject: 'Huduma ya fedha inachakatwa',
                    body: `Ombi lako la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} la ${amount || currency} kupitia ${actorLabel} linachakatwa.`,
                },
                AGENT_CUSTOMER_CASH_COMPLETED: {
                    subject: 'Huduma ya fedha imekamilika',
                    body: `Ombi lako la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} la ${amount || currency} kupitia ${actorLabel} limekamilika kwa mafanikio.`,
                },
                AGENT_CUSTOMER_CASH_FAILED: {
                    subject: 'Taarifa ya huduma ya fedha',
                    body: `Ombi lako la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} kupitia ${actorLabel} halijakamilika. Angalia shughuli zako za karibuni kwa maelezo.`,
                },
                AGENT_COMMISSION_PAID: {
                    subject: 'Kamisheni ya agent imelipwa',
                    body: `Kamisheni ya ${amount || currency} imeingizwa kwenye akaunti yako ya agent ya ORBI.`,
                },
                SERVICE_CUSTOMER_REGISTERED: {
                    subject: 'Mteja ameongezwa kwa mafanikio',
                    body: `${customerLabel} ameongezwa kupitia ${actorLabel} na sasa ameunganishwa na huduma zako.`,
                },
                SERVICE_CUSTOMER_ONBOARDED: {
                    subject: 'Akaunti yako ya ORBI iko tayari',
                    body: `Akaunti yako ya ORBI imefunguliwa kwa mafanikio na imeunganishwa na ${actorLabel}.`,
                },
                SERVICE_ACCESS_APPROVED: {
                    subject: 'Huduma imeidhinishwa',
                    body: `Ufikiaji wako wa ORBI umesasishwa. ${actorLabel} sasa inapatikana kwenye akaunti yako.`,
                },
            },
        } as const;

        const copy = translations[language][event] || translations.en[event];
        const templateMap = {
            MERCHANT_PAYMENT_PENDING: 'Merchant_Service_Update',
            MERCHANT_PAYMENT_COMPLETED: 'Merchant_Service_Update',
            MERCHANT_PAYMENT_FAILED: 'Merchant_Service_Update',
            MERCHANT_CUSTOMER_PAYMENT_PENDING: 'Merchant_Customer_Payment_Update',
            MERCHANT_CUSTOMER_PAYMENT_COMPLETED: 'Merchant_Customer_Payment_Update',
            MERCHANT_CUSTOMER_PAYMENT_FAILED: 'Merchant_Customer_Payment_Update',
            AGENT_CASH_PENDING: 'Agent_Cash_Update',
            AGENT_CASH_COMPLETED: 'Agent_Cash_Update',
            AGENT_CASH_FAILED: 'Agent_Cash_Update',
            AGENT_CUSTOMER_CASH_PENDING: 'Agent_Customer_Cash_Update',
            AGENT_CUSTOMER_CASH_COMPLETED: 'Agent_Customer_Cash_Update',
            AGENT_CUSTOMER_CASH_FAILED: 'Agent_Customer_Cash_Update',
            AGENT_COMMISSION_PAID: 'Agent_Commission_Paid',
            SERVICE_CUSTOMER_REGISTERED: 'Service_Customer_Registered',
            SERVICE_CUSTOMER_ONBOARDED: 'Service_Customer_Registered',
            SERVICE_ACCESS_APPROVED: 'Service_Access_Approved',
        } as const;

        const templateVariables: Record<string, any> = {
            refId: context.refId,
            actorLabel,
            amount: numericAmount ?? context.amount ?? 0,
            currency,
            status: String(context.status || '').toUpperCase() || (
                event.includes('FAILED')
                    ? 'FAILED'
                    : event.includes('PENDING')
                      ? 'PENDING'
                      : 'COMPLETED'
            ),
            direction: direction || 'deposit',
            customerName: customerLabel,
        };

        // Intentionally delegate channel choice to dispatch().
        // This keeps service-actor notifications aligned with the global
        // ORBI policy:
        // - language from the user's stored profile
        // - Tanzania/users with +255 or NIDA preference -> SMS first
        // - otherwise email when available
        // - otherwise WhatsApp for phone-only non-Tanzania users
        // - realtime socket push and gateway push continue to follow the same node
        return this.dispatch(userId, category, copy.subject, copy.body, {
            template: templateMap[event],
            eventCode: event,
            variables: templateVariables,
        });
    }

    /**
     * GENERATE CONTEXTUAL ALERT
     * Employs Gemini to wrap cold transaction data into professional human-readable alerts.
     */
    public async generateContextualAlert(type: 'payment' | 'security' | 'goal', context: any, userId?: string): Promise<{ subject: string, body: string }> {
        try {
            const apiKey = process.env.GEMINI_API_KEY;
            if (!apiKey) throw new Error("GEMINI_API_KEY_MISSING");
            
            let language = 'en';
            if (userId) {
                const profile = await this.getUserProfile(userId);
                language = profile.language;
            }

            const ai = new GoogleGenAI({ apiKey });
            const systemPrompt = `You are the Orbi Customer Assistant. Convert technical transaction events into friendly, simple, and clear notifications for a mobile app. 
            Avoid technical jargon like 'ledger', 'settlement', 'vault', 'node', or 'finalized'. Use words like 'payment', 'account', 'secure', or 'ready'.
            CRITICAL: Do NOT use the word 'Fynix' or 'fynix'. Always use 'Orbi'.
            LANGUAGE: Respond strictly in ${language === 'sw' ? 'Swahili (Kiswahili)' : 'English'}.
            Respond strictly in valid JSON: { "subject": "Short Title", "body": "1-sentence message" }`;
            
            const userPrompt = `Event: ${type.toUpperCase()}, Data: ${JSON.stringify(context)}. 
            If status is 'held_for_review', sound helpful but cautious about security. 
            If status is 'completed', sound cheerful and helpful.`;

            const response = await ai.models.generateContent({
                model: 'gemini-2.5-flash',
                contents: userPrompt,
                config: { 
                  systemInstruction: systemPrompt, 
                  responseMimeType: "application/json"
                }
            });
            
            const parsed = JSON.parse(response.text || '{}');
            if (parsed.subject && parsed.body) return parsed;
        } catch (e) {
            console.warn("[Messaging] Intelligence node fault, utilizing heuristic fallback.");
        }

        let language = 'en';
        if (userId) {
            const profile = await this.getUserProfile(userId);
            language = profile.language;
        }

        const fallbacks = {
            en: {
                payment: { subject: "Payment Received", body: "A credit transaction has been successfully processed and added to your account balance." },
                security: { subject: "Security Notification", body: "A security verification was performed on your account to ensure continued protection." },
                goal: { subject: "Savings Goal Update", body: "Congratulations on your progress. You are moving closer to achieving your financial goal." }
            },
            sw: {
                payment: { subject: "Malipo Yamepokelewa", body: "Muamala wa mkopo umekamilika kwa mafanikio na kuongezwa kwenye salio la akaunti yako." },
                security: { subject: "Taarifa ya Usalama", body: "Uhakiki wa usalama umefanyika kwenye akaunti yako ili kuhakikisha ulinzi unaendelea." },
                goal: { subject: "Maendeleo ya Akiba", body: "Hongera kwa hatua uliyopiga. Unakaribia kufikia lengo lako la kifedha." }
            }
        };
        const t = (fallbacks as any)[language] || fallbacks.en;
        return t[type] || { 
            subject: language === 'sw' ? "Taarifa ya Akaunti" : "Account Notification", 
            body: language === 'sw' ? "Ombi lako la hivi karibuni limeshughulikiwa kwa mafanikio." : "Your recent request has been processed successfully." 
        };
    }

    public async getMessages(userId: string, limit: number = 50, offset: number = 0): Promise<UserMessage[]> {
        const sb = getAdminSupabase();
        if (sb) {
            const { data } = await sb.from('user_messages')
                .select('id,user_id,subject,body,category,is_read,created_at')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })
                .range(offset, offset + limit - 1);
            
            // Decrypt messages before returning
            if (data) {
                return Promise.all(data.map(async (msg) => ({
                    ...msg,
                    subject: await DataProtection.decryptMessageContent(msg.subject, msg.subject),
                    body: await DataProtection.decryptMessageContent(msg.body, msg.body)
                })));
            }
        }
        return [];
    }

    public async markAsRead(userId: string, messageId: string) {
        const sb = getAdminSupabase();
        if (sb) {
            await sb.from('user_messages')
                .update({ is_read: true })
                .eq('id', messageId)
                .eq('user_id', userId);
        }
    }

    public async markAllAsRead(userId: string) {
        const sb = getAdminSupabase();
        if (sb) {
            await sb.from('user_messages')
                .update({ is_read: true })
                .eq('user_id', userId);
        }
    }

    public async deleteMessage(userId: string, messageId: string) {
        const sb = getAdminSupabase();
        if (sb) {
            await sb.from('user_messages')
                .delete()
                .eq('id', messageId)
                .eq('user_id', userId);
        }
    }

    public async sendNewDeviceAlert(userId: string, deviceName: string) {
        const subject = "Security Alert: New Device";
        const body = `A new device '${deviceName}' has been used to access your account. If this was not you, please contact support immediately.`;
        
        await this.dispatch(userId, 'security', subject, body, {
            template: 'New_Device_Alert',
            variables: { deviceName }
        });
    }
}

export const Messaging = new MessagingService();
