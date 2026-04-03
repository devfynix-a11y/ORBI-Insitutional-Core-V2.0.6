
import { getSupabase, getAdminSupabase } from './supabaseClient.js';
import { AuthService } from '../iam/authService.js';
import { TransactionService } from '../ledger/transactionService.js';
import { WalletService } from '../wealth/walletService.js';
import { GoalService } from '../strategy/goalService.js';
import { CategoryService } from '../strategy/categoryService.js';
import { TaskService } from '../strategy/taskService.js';
import { Audit } from './security/audit.js';
import { 
    AppData, Transaction, Wallet, Goal, StaffMember, UserRole, 
    FinancialOverview, ForensicReport, DisputeCase, PricingRule, 
    RegisteredApp, SystemMessage, UserMessage, UserActivity, 
    SupportTicket, RegulatoryConfig 
} from '../types.js';
import { SecurityService } from '../iam/securityService.js';
import { RegulatoryService } from '../ledger/regulatoryService.js';
import { DisputeService } from '../ledger/disputeService.js';
import { EscrowService } from '../ledger/escrowService.js';
import { RevenueService } from '../wealth/revenueService.js';
import { InfraPersistence } from './persistence/infraPersistence.js';
import { AssetLifecycle } from './features/AssetLifecycle.js';
import { Sentinel } from './security/sentinel.js';
import { ConfigClient } from './infrastructure/RulesConfigClient.js';
import { DEFAULT_INSTITUTIONAL_APP_ORIGIN } from './config/appIdentity.js';
import { CONFIG } from '../services/config.js';
import { FinancialLogic } from '../services/financialLogic.js';
import { VaultAuditor } from './security/vaultAuditor.js';
import { Messaging } from './features/MessagingService.js';
import { orbiGatewayService } from './infrastructure/orbiGatewayService.js';
import { ReconEngine } from './ledger/reconciliationService.js';
import { OTPService } from './security/otpService.js';
import { InternalBroker } from '../BROKER/index.js';
import { UUID, IdentityGenerator } from '../services/utils.js';
// emailService removed as per user request.

import { SystemPilot } from './infrastructure/AutonomousCore.js';
import { HealthMonitor } from './infrastructure/HealthMonitor.js';
import { DataVault } from './security/encryption.js';
import { ProviderAnomalyTracker } from './security/ProviderAnomalyTracker.js';
import { Identity } from '../iam/identityService.js';
import { KYCService } from '../iam/kycService.js';
import { DeviceService } from '../iam/deviceService.js';
import { DocumentService } from '../iam/documentService.js';
import { Merchants } from '../wealth/merchantService.js';
import { MerchantAccounts } from './wealth/merchantAccountService.js';
import { FinancialCore } from './core/FinancialCoreEngine.js';
import { SettlementEngine } from './core/SettlementEngine.js';
import { EntProcessor } from './enterprise/wealth/EnterprisePaymentProcessor.js';
import { Treasury } from './enterprise/treasuryService.js';
import { RiskComplianceEngine } from './security/RiskComplianceEngine.js';
import { PartnerRegistry } from './admin/partnerRegistry.js';
import { ServiceActorOps } from './features/ServiceActorOps.js';
import { institutionalFundsService } from './payments/InstitutionalFundsService.js';
import { platformFeeService } from './payments/PlatformFeeService.js';
import { offlineGatewayService } from './offline/OfflineGatewayService.js';
import { buildPostgrestOrFilter } from './security/postgrest.js';
import bcrypt from 'bcryptjs';

const internalBackgroundJobsEnabled =
    process.env.ORBI_ENABLE_INTERNAL_BACKGROUND_JOBS === 'true';

class OrbiServer {
// ...
    async submitKYC(userId: string, data: any) { 
        const result = await KYCService.submitKYC(userId, data); 
        // Push a task to the internal broker for background validation
        await InternalBroker.push('AI_REPORT_GEN', { userId, kycData: data });
        return result;
    }
    async getKYCStatus(userId: string) { return KYCService.getKYCStatus(userId); }
    async scanKYC(imageBuffer: Buffer, mimeType: string) { return KYCService.scanKYC(imageBuffer, mimeType); }
    async uploadKYCDocument(userId: string, file: Buffer, fileName: string, contentType: string) {
        return KYCService.uploadDocument(userId, file, fileName, contentType);
    }
    async reviewKYC(requestId: string, adminId: string, decision: any, reason?: string) { 
        const result = await KYCService.reviewKYC(requestId, adminId, decision, reason); 
        return result;
    }
    async getKYCRequests(status?: string, limit?: number, offset?: number) { return KYCService.getKYCRequests(status, limit, offset); }
    
    // --- RISK & COMPLIANCE ---
    async getPendingAMLAlerts() { return RiskComplianceEngine.getPendingAlerts(); }
    async updateAMLAlertStatus(alertId: string, status: 'INVESTIGATING' | 'CLEARED' | 'BLOCKED') { return RiskComplianceEngine.updateAlertStatus(alertId, status); }
    async generateRegulatoryReport(startDate: string, endDate: string) { return RiskComplianceEngine.generateRegulatoryReport(startDate, endDate); }

    // --- DEVICES ---
    async registerDevice(userId: string, data: any) { return DeviceService.registerDevice(userId, data); }
    async getUserDevices(userId: string) { return DeviceService.getUserDevices(userId); }
    async removeDevice(userId: string, deviceId: string) { return DeviceService.removeDevice(userId, deviceId); }
    async getAllDevices(limit?: number, offset?: number) { return DeviceService.getAllDevices(limit, offset); }
    async updateDeviceStatus(deviceId: string, data: any) { return DeviceService.updateDeviceStatus(deviceId, data); }

    // --- DOCUMENTS ---
    async uploadDocument(userId: string, data: any) { return DocumentService.uploadDocument(userId, data); }
    async getUserDocuments(userId: string) { return DocumentService.getUserDocuments(userId); }
    async removeDocument(userId: string, documentId: string) { return DocumentService.removeDocument(userId, documentId); }
    async getAllDocuments(limit?: number, offset?: number) { return DocumentService.getAllDocuments(limit, offset); }
    async verifyDocument(documentId: string, adminId: string, data: any) { return DocumentService.verifyDocument(documentId, adminId, data); }

    constructor() {
        // Start Autonomous Systems
        SystemPilot.start();
        HealthMonitor.start();

        // Start External Broker Listener (Worker Mode)
        // Note: InternalBroker now handles its own internal polling and heartbeat.

        // Start Background Jobs only when this process is explicitly promoted to
        // a worker role. The gateway runtime already runs its own scheduler.
        if (internalBackgroundJobsEnabled) {
            let backgroundJobRunning = false;
            setInterval(async () => {
                if (backgroundJobRunning) {
                    return;
                }
                backgroundJobRunning = true;
                try {
                    await ReconEngine.reapStuckTransactions();
                    await EntProcessor.settleProcessingTransactions();
                    await Treasury.sweepAllOrganizations();
                } catch (e) {
                    console.error("[BackgroundJob] Cycle failed:", e);
                } finally {
                    backgroundJobRunning = false;
                }
            }, CONFIG.BACKGROUND_JOB_INTERVAL); // Run every configured interval
        }
    }

    async warmup() {
        console.info("[OrbiServer] Warming up critical services...");
        await Promise.all([
            ReconEngine.reapStuckTransactions(),
            EntProcessor.settleProcessingTransactions(),
            SystemPilot.start()
        ]);
        console.info("[OrbiServer] Critical services warmed up.");
    }
    private auth = new AuthService();
    private ledger = new TransactionService();
    private wallet = new WalletService();
    private goal = new GoalService();
    private category = new CategoryService();
    private task = new TaskService();
    private security = new SecurityService();
    private escrow = new EscrowService();

    // --- IAM & IDENTITY ---
    async login(e: string | undefined, p: string, metadata?: any) { return this.auth.login(e || '', p, metadata); }
    async signUp(email: string | undefined, password: string, metadata?: any, appId?: string) { 
        return this.auth.signUp(email || '', password, { ...metadata, app_origin: metadata?.app_origin || appId }); 
    }
    async getSession(token?: string) { return this.auth.getSession(token); }
    async refreshSession(refreshToken: string, metadata?: any) { return this.auth.refreshSession(refreshToken, metadata); }
    async logout(token?: string, refreshToken?: string) { return this.auth.logout(token, refreshToken); }
    async lookupUser(query: string) { return Identity.lookupUser(query); }
    
    async updatePassword(password: string) { return this.auth.updatePassword(password); }
    async completePasswordReset(password: string) { return this.auth.completePasswordReset(password); }
    async initiatePasswordReset(identifier: string) { return this.auth.initiatePasswordReset(identifier); }
    async deleteAccount() { return this.auth.deleteAccount(); }
    async initiatePhoneLogin(phone: string) { return this.auth.initiatePhoneLogin(phone); }
    async verifyPhoneLogin(phone: string, token: string) { return this.auth.verifyPhoneLogin(phone, token); }
    async completeProfile(phone: string, updates: any) { return this.auth.completeProfile(phone, updates); }
    async getUserProfile(userId: string) { return this.auth.getUserProfile(userId); }
    async registerBiometric(userId: string, credential: any) { return this.auth.registerBiometric(userId, credential); }
    async generateSecureConnection(token?: string) { return { status: 'SECURE', node: 'DPS-PRIMARY-RELAY', ts: Date.now() }; }

    // --- DIAGNOSTICS ---
    async testEmail(to: string) {
        console.info(`[OrbiServer] Email test requested for ${to} via ORBI Gateway.`);
        const success = await orbiGatewayService.sendEmail(
            to,
            'ORBI Gateway Test',
            'This is a test email from the ORBI Sovereign Node via the internal ORBI Gateway.',
            undefined,
            'en',
            undefined,
            undefined,
            `test-${Date.now()}`
        );
        return { success };
    }

    async verifyEmailConfig() {
        console.info(`[OrbiServer] Email config verification via ORBI Gateway.`);
        const isConfigured = Boolean(process.env.ORBI_GATEWAY_API_KEY && (process.env.ORBI_GATEWAY_URL || process.env.ORBI_GATEWAY_BASE_URL));
        return { status: isConfigured ? 'ACTIVE' : 'MISSING_CONFIG' };
    }

    // --- SENSITIVE ACTIONS & OTP ---
    async initiateSensitiveAction(userId: string, contact: string, action: string, type?: 'sms' | 'email' | 'push' | 'whatsapp', deviceName: string = 'Unknown Device') {
        const resolvedType = type || (contact.includes('@') ? 'email' : 'sms');
        const result = await OTPService.generateAndSend(userId, contact, action, resolvedType, deviceName);
        if (result.requestId === 'ERROR_NO_CONTACT') {
            throw new Error("No contact method provided for verification.");
        }
        if (result.requestId === 'THROTTLED') {
            throw new Error("Too many requests. Please wait 60 seconds.");
        }
        return result;
    }

    async verifySensitiveAction(requestId: string, code: string, userId: string) {
        const isValid = await OTPService.verify(requestId, code, userId);
        if (isValid) {
            await this.security.logActivity(userId, 'SENSITIVE_ACTION_VERIFIED', 'success', `Action verified via OTP`);
            return { success: true };
        }
        await this.security.logActivity(userId, 'SENSITIVE_ACTION_FAILED', 'failure', `OTP verification failed`);
        return { success: false, error: 'INVALID_OTP' };
    }

    // --- BOOTSTRAP ---
    async getBootstrapData(token?: string): Promise<AppData> {
        const session = await this.auth.getSession(token);
        if (!session) throw new Error("IDENTITY_REQUIRED");
        
        const [transactions, wallets, goals, categories, tasks, messages] = await Promise.all([
            this.ledger.getLatestTransactions(session.sub),
            this.wallet.fetchForUser(session.sub),
            this.goal.fetchForUser(session.sub, token || session.access_token),
            this.category.fetchForUser(session.sub),
            this.task.fetchForUser(session.sub),
            this.getUserMessages(session.sub)
        ]);

        return {
            transactions,
            wallets,
            financialGoals: goals,
            categories,
            tasks,
            userProfile: {
                ...session.user.user_metadata,
                kyc_status: session.user.user_metadata?.kyc_status || 'unverified',
                first_name: session.user.user_metadata?.full_name?.split(' ')[0] || 'Customer'
            },
            goalAllocations: [],
            messages,
            systemMessages: await this.getSystemMessages()
        };
    }

    // --- PAGINATED LEDGER ---
    async getTransactionsPaginated(userId: string, limit: number, offset: number) {
        return this.ledger.getLatestTransactions(userId, limit, offset);
    }

    async requestTransactionRecall(userId: string, txId: string, reason: string) {
        return this.ledger.lockTransactionForReview(txId, userId, {
            actorRole: 'USER',
            reason,
            requestReverse: true,
            userLock: true,
            reviewWindowHours: 24,
        });
    }

    async lockTransactionForAdmin(actorId: string, txId: string, reason: string) {
        return this.ledger.lockTransactionForReview(txId, actorId, {
            actorRole: 'STAFF',
            reason,
            requestReverse: false,
            userLock: false,
            reviewWindowHours: 24,
        });
    }

    async reverseTransactionForAdmin(actorId: string, txId: string, reason: string) {
        return this.ledger.reverseTransactionWithReason(txId, actorId, reason, 'STAFF');
    }

    async recordTransactionAuditDecision(actorId: string, txId: string, passed: boolean, notes: string) {
        return this.ledger.recordAuditDecision(txId, actorId, passed, notes, 'STAFF');
    }

    async approveReviewedTransaction(actorId: string, txId: string, notes: string) {
        return this.ledger.approveReviewedTransaction(txId, actorId, notes);
    }

    async approveAllAuditPassedTransactions(actorId: string, notes: string) {
        return this.ledger.approveAllAuditPassedTransactions(actorId, notes);
    }

    // --- TRANSACTION PREVIEW ---
    async getTransactionPreview(userId: string, payload: any) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error("DB_OFFLINE");
        const requestCurrency = typeof payload?.currency === 'string'
            ? payload.currency.trim().toUpperCase()
            : '';
        if (!requestCurrency) {
            throw new Error("CURRENCY_REQUIRED: Transaction preview requires an explicit currency.");
        }
        
        // Fetch user to ensure they exist and get metadata
        const { data: authUser } = await sb.auth.admin.getUserById(userId);
        if (!authUser || !authUser.user) throw new Error("IDENTITY_NOT_FOUND");

        // Fetch real status from public profile to ensure Rules Engine sees the correct status
        const { data: profile } = await sb.from('users').select('account_status').eq('id', userId).single();
        
        const user = authUser.user;
        if (profile) {
            user.user_metadata = {
                ...user.user_metadata,
                account_status: profile.account_status
            };
        }

        const result = await EntProcessor.process(user as any, { 
            idempotencyKey: payload.idempotencyKey || `preview-${Date.now()}`,
            sourceWalletId: payload.sourceWalletId,
            targetWalletId: payload.targetWalletId,
            recipientId: payload.recipientId,
            recipient_customer_id: payload.recipient_customer_id,
            amount: payload.amount,
            currency: requestCurrency,
            description: payload.description || 'Preview',
            type: payload.type || 'INTERNAL_TRANSFER',
            metadata: payload.metadata,
            dryRun: true 
        } as any);

        return result;
    }

    // --- WEALTH & SETTLEMENT ---
    async calculateSettlementBreakdown(payload: any) {
        const session = await this.auth.getSession();
        if (!session) throw new Error("IDENTITY_REQUIRED");
        const requestCurrency = typeof payload?.currency === 'string'
            ? payload.currency.trim().toUpperCase()
            : '';
        if (!requestCurrency) {
            throw new Error("CURRENCY_REQUIRED: Settlement breakdown requires an explicit currency.");
        }
        return EntProcessor.process(session.user as any, { 
            idempotencyKey: payload.idempotencyKey || `calc-${Date.now()}`,
            sourceWalletId: payload.sourceWalletId,
            targetWalletId: payload.targetWalletId,
            recipientId: payload.recipientId,
            recipient_customer_id: payload.recipient_customer_id,
            amount: payload.amount,
            currency: requestCurrency,
            description: payload.description || 'Calculation',
            type: payload.type || 'INTERNAL_TRANSFER',
            walletType: payload.walletType,
            category: payload.category,
            metadata: payload.metadata,
            dryRun: true 
        } as any);
    }

    async processSecurePayment(payload: any, user?: any) {
        const sessionUser = user || (await this.auth.getSession())?.user;
        if (!sessionUser) throw new Error("IDENTITY_REQUIRED");
        const requestCurrency = typeof payload?.currency === 'string'
            ? payload.currency.trim().toUpperCase()
            : '';
        if (!requestCurrency) {
            throw new Error("CURRENCY_REQUIRED: Secure payment requires an explicit currency.");
        }
        
        const result = await EntProcessor.process(sessionUser as any, {
            idempotencyKey: payload.idempotencyKey || `tx-${Date.now()}-${Math.random()}`,
            referenceId: payload.referenceId,
            sourceWalletId: payload.sourceWalletId,
            targetWalletId: payload.targetWalletId,
            recipientId: payload.recipientId,
            recipient_customer_id: payload.recipient_customer_id,
            amount: payload.amount,
            currency: requestCurrency,
            description: payload.description || 'Secure Payment',
            type: payload.type || 'INTERNAL_TRANSFER',
            walletType: payload.walletType,
            category: payload.category,
            categoryId: payload.categoryId,
            metadata: payload.metadata
        } as any);

        if (result?.success && result.transaction) {
            await ServiceActorOps.handleTransactionPosted(sessionUser, payload, result.transaction);

            const sourceTransactionId = String(result.transaction.internalId || result.transaction.id || '');
            const normalizedType = String(payload?.type || '').trim().toUpperCase();
            const cashDirection = String(payload?.metadata?.cash_direction || '').trim().toLowerCase();
            const triggerType =
                normalizedType === 'SALARY'
                    ? 'SALARY'
                    : normalizedType === 'DEPOSIT' && cashDirection === 'deposit'
                        ? 'AGENT_CASH_DEPOSIT'
                        : normalizedType === 'DEPOSIT'
                            ? 'DEPOSIT'
                            : null;

            if (sourceTransactionId && triggerType) {
                try {
                    await this.goal.runAutoAllocationsForCredit({
                        userId: String(sessionUser.id),
                        sourceTransactionId,
                        sourceReferenceId: result.transaction.referenceId || result.transaction.id || null,
                        sourceWalletId: result.transaction.toWalletId || payload?.targetWalletId || null,
                        sourceAmount: Number(payload?.amount || result.transaction.amount || 0),
                        currency: payload?.currency || result.transaction.currency || null,
                        triggerType,
                        metadata: {
                            source: 'secure_payment',
                            payment_type: normalizedType,
                            service_context: payload?.metadata?.service_context || null,
                        },
                    });
                } catch (autoAllocationError: any) {
                    console.error('[GoalAutoAllocation] Secure payment trigger failed:', autoAllocationError?.message || autoAllocationError);
                }
            }
        }

        return result;
    }

    async postWallet(p: any) { 
        const session = await this.auth.getSession();
        if (!session) throw new Error("IDENTITY_REQUIRED");
        return this.wallet.createLinkedWallet(p.userId || session.sub, p); 
    }
    
    async updateWallet(p: any) { return this.wallet.updateWallet(p.id, p); }
    async getWallets(uid: string) { return this.wallet.fetchForUser(uid); }
    async deleteWallet(userId: string, id: string) {
        return this.wallet.deleteWallet(id, 'linked', userId);
    }

    private async verifyTransactionPin(userId: string, pin?: string): Promise<boolean> {
        if (!pin || !pin.trim()) return false;
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');
        const { data: profile } = await sb
            .from('users')
            .select('security_tx_pin_hash, security_tx_pin_enabled')
            .eq('id', userId)
            .maybeSingle();
        if (!profile?.security_tx_pin_enabled || !profile.security_tx_pin_hash) {
            throw new Error('PIN_NOT_SET');
        }
        const hash = String(profile.security_tx_pin_hash || '');
        if (hash.startsWith('$2')) {
            return await bcrypt.compare(pin.trim(), hash);
        }
        return pin.trim() === hash;
    }

    private async resolveWalletRecord(walletId: string) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');
        const { data: vault } = await sb
            .from('platform_vaults')
            .select('id, user_id, status, is_locked, locked_at, lock_reason, metadata')
            .eq('id', walletId)
            .maybeSingle();
        if (vault) return { table: 'platform_vaults', record: vault };

        const { data: wallet } = await sb
            .from('wallets')
            .select('id, user_id, status, is_locked, locked_at, lock_reason, metadata')
            .eq('id', walletId)
            .maybeSingle();
        if (wallet) return { table: 'wallets', record: wallet };
        return null;
    }

    private isHardBlockedStatus(status?: string | null) {
        if (!status) return false;
        return status.trim().toLowerCase() === 'blocked';
    }

    private shouldForceUnlockStatus(status?: string | null) {
        if (!status) return false;
        const normalized = status.trim().toLowerCase();
        return ['locked', 'frozen', 'suspended', 'blocked'].includes(normalized);
    }

    async lockWallet(
        actorUserId: string,
        walletId: string,
        opts: { reason?: string; pin?: string; force?: boolean; isAdmin?: boolean } = {}
    ) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const resolved = await this.resolveWalletRecord(walletId);
        if (!resolved) throw new Error('WALLET_NOT_FOUND');

        const { table, record } = resolved;
        const isOwner = record.user_id === actorUserId;
        if (!opts.isAdmin && !isOwner) throw new Error('ACCESS_DENIED');

        if (!opts.isAdmin && opts.pin) {
            const ok = await this.verifyTransactionPin(actorUserId, opts.pin);
            if (!ok) throw new Error('INVALID_PIN');
        }

        const reason = opts.reason || (opts.isAdmin ? 'Admin lock' : 'User lock');
        const updatePayload: any = {
            is_locked: true,
            status: 'locked',
            locked_at: new Date().toISOString(),
            lock_reason: reason
        };

        const { error } = await sb.from(table).update(updatePayload).eq('id', record.id);
        if (error) throw error;

        return { ...record, ...updatePayload, table };
    }

    async unlockWallet(
        actorUserId: string,
        walletId: string,
        opts: { pin?: string; force?: boolean; isAdmin?: boolean } = {}
    ) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const resolved = await this.resolveWalletRecord(walletId);
        if (!resolved) throw new Error('WALLET_NOT_FOUND');

        const { table, record } = resolved;
        const isOwner = record.user_id === actorUserId;
        if (!opts.isAdmin && !isOwner) throw new Error('ACCESS_DENIED');

        if (!opts.isAdmin) {
            const ok = await this.verifyTransactionPin(actorUserId, opts.pin);
            if (!ok) throw new Error('INVALID_PIN');
            if (this.isHardBlockedStatus(record.status)) {
                throw new Error('WALLET_BLOCKED');
            }
        }

        const nextStatus = (opts.isAdmin || this.shouldForceUnlockStatus(record.status))
            ? 'active'
            : record.status;
        const updatePayload: any = {
            is_locked: false,
            status: nextStatus,
            locked_at: null,
            lock_reason: null
        };

        const { error } = await sb.from(table).update(updatePayload).eq('id', record.id);
        if (error) throw error;

        return { ...record, ...updatePayload, table };
    }

    // --- ESCROW & TRUSTLESS COMMERCE ---
    async createEscrow(userId: string, recipientCustomerId: string, amount: number, description: string, conditions: any) {
        return this.escrow.createEscrow(userId, recipientCustomerId, amount, description, conditions);
    }
    async getEscrows(userId: string) {
        return this.escrow.getEscrows(userId);
    }
    async getEscrow(referenceId: string) {
        return this.escrow.getEscrow(referenceId);
    }
    async releaseEscrow(referenceId: string, actorId: string) {
        return this.escrow.releaseEscrow(referenceId, actorId);
    }
    async disputeEscrow(referenceId: string, userId: string, reason: string) {
        return this.escrow.disputeEscrow(referenceId, userId, reason);
    }
    async refundEscrow(referenceId: string, adminId: string) {
        return this.escrow.refundEscrow(referenceId, adminId);
    }

    // --- RECONCILIATION ---
    async triggerManualRecon(providerId: string) {
        return ReconEngine.runDailyRecon(providerId);
    }

    // --- STRATEGY & PLANNING ---
    async postGoal(p: any, token?: string) { return this.goal.postGoal(p, token); }
    async updateGoal(p: any, token?: string) { return this.goal.updateGoal(p, token); }
    async allocateToGoal(goalId: string, amount: number, walletId: string, token?: string) {
        return this.goal.allocateFunds(goalId, amount, walletId, token);
    }
    async runGoalAutoAllocationsForCredit(payload: {
        userId: string;
        sourceTransactionId: string;
        sourceReferenceId?: string | null;
        sourceWalletId?: string | null;
        sourceAmount: number;
        currency?: string | null;
        triggerType: string;
        metadata?: Record<string, any>;
    }) {
        return this.goal.runAutoAllocationsForCredit(payload);
    }
    async replayGoalAutoAllocations(userId: string, sourceTransactionId: string, token?: string) {
        return this.goal.replayAutoAllocationsForTransaction(userId, sourceTransactionId, token);
    }
    async withdrawFromGoal(goalId: string, amount: number, walletId: string, verification?: any, token?: string) {
        return this.goal.withdrawFunds(goalId, amount, walletId, verification, token);
    }
    async deleteGoal(id: string, token?: string) { return this.goal.deleteGoal(id, token); }
    async getGoals(userId: string, token?: string) { return this.goal.fetchForUser(userId, token); }
    async postCategory(p: any, token?: string) { return this.category.postCategory(p, token); }
    async getCategories(userId: string, token?: string) { return this.category.fetchForUser(userId, token); }
    async updateCategory(p: any, token?: string) { return this.category.updateCategory(p, token); }
    async deleteCategory(id: string, token?: string) { return this.category.deleteCategory(id, token); }
    async postTask(p: any) { return this.task.postTask(p); }
    async getTasks(userId: string) { return this.task.fetchForUser(userId); }
    async updateTask(p: any) { return this.task.updateTask(p); }
    async deleteTask(id: string) { return this.task.deleteTask(id); }

    // --- INFRASTRUCTURE & METRICS ---
    async testConnection() { return { status: 'ONLINE', ts: Date.now() }; }
    async getSystemMetrics() {
        return { throughput: '4.2k TPS', uptime: '99.999%', active_nodes: 12, health: 'OPTIMAL' };
    }
    async persistInfraSnapshot(snapshot: any) { return InfraPersistence.saveSnapshot(snapshot.actorId || 'system', snapshot); }
    async getApps() { return RegulatoryService.getApps(); }
    async registerApp(name: string, tier: string) { return RegulatoryService.registerApp(name, tier); }
    async verifyAppNode(id: string, token: string) { return RegulatoryService.verifyAppNode(id, token); }

    // --- GOVERNANCE & STAFF ---
    async getAllStaff(): Promise<StaffMember[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];
        const { data } = await sb.from('staff').select('*').order('created_at', { ascending: false });
        return (data || []).map((staff: any) => ({
            ...staff,
            effective_permissions: this.auth.describePermissionsForRole(
                String(staff.role || 'USER').toUpperCase() as any,
                String(staff.account_status || 'active').toLowerCase(),
            ),
        }));
    }
    async getAllConsumers(): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];
        const { data } = await sb.from('users').select('*');
        return data || [];
    }
    async getBootstrapState() {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { staffCount: 0, bootstrapRequired: true };
        const { count } = await sb.from('staff').select('id', { count: 'exact', head: true });
        const staffCount = count || 0;
        return {
            staffCount,
            bootstrapRequired: staffCount === 0
        };
    }
    async createStaff(payload: any, actorId: string) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        const normalizedOrigin = String(payload?.app_origin || DEFAULT_INSTITUTIONAL_APP_ORIGIN).trim();
        const normalizedRole = String(payload?.role || 'ADMIN').trim().toUpperCase();
        const normalizedLanguage = String(payload?.language || 'en').trim().toLowerCase() || 'en';

        if (payload?.phone) {
            const { data: existingUser } = await sb
                .from('users')
                .select('id')
                .eq('phone', payload.phone)
                .maybeSingle();
            if (existingUser) {
                return { error: 'PHONE_ALREADY_IN_USE: This phone number is already linked to another account.' };
            }

            const { data: existingStaff } = await sb
                .from('staff')
                .select('id')
                .eq('phone', payload.phone)
                .maybeSingle();
            if (existingStaff) {
                return { error: 'PHONE_ALREADY_IN_USE: This phone number is already linked to another account.' };
            }
        }
        
        // 1. Create Auth User
        const { data: authData, error: authError } = await sb.auth.admin.createUser({
            email: payload.email,
            password: payload.password,
            user_metadata: {
                full_name: payload.full_name,
                role: normalizedRole,
                registry_type: 'STAFF',
                account_status: 'active',
                app_origin: normalizedOrigin,
                language: normalizedLanguage
            },
            email_confirm: true
        });

        if (authError) return { error: authError.message };
        if (!authData.user) return { error: 'USER_CREATION_FAILED' };

        // 2. Create Staff Profile
        const { error: profileError } = await sb.from('staff').insert({
            id: authData.user.id,
            email: payload.email,
            full_name: payload.full_name,
            role: normalizedRole,
            phone: payload.phone,
            nationality: payload.nationality,
            avatar_url: payload.avatar_url,
            address: payload.address,
            language: normalizedLanguage,
            account_status: 'active',
            customer_id: IdentityGenerator.generateCustomerID('STF')
        });

        if (profileError) {
            // Rollback auth user
            await sb.auth.admin.deleteUser(authData.user.id);
            return { error: profileError.message };
        }

        await this.security.logActivity(actorId, 'STAFF_CREATION', 'success', `Created staff member ${payload.email} with role ${payload.role}`);
        return { success: true, data: { id: authData.user.id } };
    }
    async createManagedIdentity(payload: any, actorId: string) {
        const publicRoleRegistryMap: Record<string, 'CONSUMER' | 'MERCHANT' | 'AGENT'> = {
            CONSUMER: 'CONSUMER',
            USER: 'CONSUMER',
            MERCHANT: 'MERCHANT',
            AGENT: 'AGENT',
        };
        const targetRegistryType = publicRoleRegistryMap[String(payload.role || '').toUpperCase()];
        if (targetRegistryType) {
            const result = await this.auth.signUp(payload.email || '', payload.password, {
                full_name: payload.full_name,
                phone: payload.phone,
                nationality: payload.nationality,
                address: payload.address,
                currency: payload.currency || 'USD',
                language: payload.language || 'en',
                role: payload.role,
                registry_type: targetRegistryType,
                app_origin: DEFAULT_INSTITUTIONAL_APP_ORIGIN,
                created_via_admin_portal: true
            });
            if (result?.error) return { error: result.error.message || result.error };
            await this.security.logActivity(
                actorId,
                'IDENTITY_CREATION',
                'success',
                `Created managed ${targetRegistryType.toLowerCase()} ${payload.email} with role ${payload.role}`,
            );
            return { success: true, data: result.data };
        }
        return this.createStaff(payload, actorId);
    }
    async bootstrapAdmin(payload: any) {
        const state = await this.getBootstrapState();
        if (!state.bootstrapRequired) {
            return { error: 'BOOTSTRAP_ALREADY_COMPLETED' };
        }
        return this.createStaff({
            ...payload,
            role: 'SUPER_ADMIN'
        }, 'bootstrap-admin');
    }

    async adminUpdateStaffProfile(staffId: string, updates: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        const { data: authUserResult, error: authUserError } = await sb.auth.admin.getUserById(staffId);
        if (authUserError || !authUserResult?.user) {
            return { error: authUserError?.message || 'STAFF_NOT_FOUND' };
        }

        const currentMetadata = authUserResult.user.user_metadata || {};
        const metadataUpdates: Record<string, unknown> = { ...currentMetadata };
        const staffUpdates: Record<string, unknown> = {};

        const assignField = (key: string) => {
            if (updates[key] !== undefined) {
                metadataUpdates[key] = updates[key];
                staffUpdates[key] = updates[key];
            }
        };

        assignField('full_name');
        assignField('phone');
        assignField('nationality');
        assignField('address');
        assignField('language');
        assignField('avatar_url');

        if (updates.role !== undefined) {
            metadataUpdates.role = String(updates.role).trim().toUpperCase();
            staffUpdates.role = String(updates.role).trim().toUpperCase();
        }

        if (updates.account_status !== undefined) {
            metadataUpdates.account_status = String(updates.account_status).trim().toLowerCase();
            staffUpdates.account_status = String(updates.account_status).trim().toLowerCase();
        }

        const { error: authUpdateError } = await sb.auth.admin.updateUserById(staffId, {
            user_metadata: metadataUpdates,
        });
        if (authUpdateError) {
            return { error: authUpdateError.message };
        }

        if (Object.keys(staffUpdates).length > 0) {
            const { error: staffError } = await sb
                .from('staff')
                .update(staffUpdates)
                .eq('id', staffId);
            if (staffError) {
                return { error: staffError.message };
            }
        }

        await this.security.logActivity(actorId, 'STAFF_PROFILE_UPDATE', 'success', `Updated staff ${staffId}`);
        return { success: true };
    }

    async adminResetStaffPassword(staffId: string, password: string, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        const { error } = await sb.auth.admin.updateUserById(staffId, { password });
        if (error) {
            return { error: error.message };
        }

        await this.security.logActivity(actorId, 'STAFF_PASSWORD_RESET', 'success', `Reset password for staff ${staffId}`);
        return { success: true };
    }

    async adminUpdateUserProfile(targetUserId: string, updates: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        // 1. Get current metadata to merge
        const { data: user, error: getError } = await sb.auth.admin.getUserById(targetUserId);
        const currentMetadata = user?.user?.user_metadata || {};

        // 2. Update public profile
        const { error: dbError } = await sb.from('users').update(updates).eq('id', targetUserId);
        if (dbError) return { error: dbError.message };

        // 3. Update Auth Metadata if needed (for critical fields)
        if (updates.full_name || updates.kyc_level || updates.kyc_status || updates.role || updates.account_status) {
            await sb.auth.admin.updateUserById(targetUserId, {
                user_metadata: { ...currentMetadata, ...updates }
            });
        }

        await this.security.logActivity(actorId, 'ADMIN_PROFILE_UPDATE', 'success', `Updated profile for user ${targetUserId}`);
        return { success: true };
    }

    async updateAccountStatus(userId: string, status: string, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return;

        // 1. Update public tables
        await sb.from('staff').update({ account_status: status }).eq('id', userId);
        await sb.from('users').update({ account_status: status }).eq('id', userId);

        // 2. Update Auth Metadata for immediate enforcement
        const { data: user } = await sb.auth.admin.getUserById(userId);
        if (user?.user) {
            await sb.auth.admin.updateUserById(userId, {
                user_metadata: { ...user.user.user_metadata, account_status: status }
            });
        }

        await this.security.logActivity(actorId, 'GOVERNANCE_STATUS_UPDATE', 'success', `Node ${userId} rotated to ${status}`);
    }
    async getForensicState(): Promise<ForensicReport> { return VaultAuditor.getForensicReport(); }
    async getDetailedUserActivity(uid: string) { return this.security.getUserActivity(uid); }

    // --- DISPUTE RESOLUTION ---
    async getDisputes() { return DisputeService.getAllCases(); }
    async resolveDispute(caseId: string, action: string, notes: string) { return DisputeService.resolveCase(caseId, action as any, notes, 'system'); }

    // --- REVENUE & FISCAL ---
    async getPricingRules() { return RevenueService.getRules(); }
    async rotatePricingRule(id: string, updates: any) { return RevenueService.rotateRule(id, updates, 'system'); }
    async getRegulatoryConfig() { return RegulatoryService.getActiveRegistry(); }
    async updateRegulatoryConfig(config: any) { return RegulatoryService.updateRegistry(config, 'system'); }
    async getSystemNodeMappings() { return RegulatoryService.getSystemNodeMappings(); }
    async updateSystemNode(role: string, walletId: string) { return RegulatoryService.updateSystemNode(role as any, walletId); }

    async getMerchants(category?: any) { return Merchants.getMerchants(category); }
    async getMerchantCategories() { return Merchants.getCategories(); }

    // --- MULTI-TENANT MERCHANT ACCOUNTS ---
    async createMerchantAccount(userId: string, data: any) { return MerchantAccounts.createMerchant(userId, data); }
    async getUserMerchantAccounts(userId: string) { return MerchantAccounts.getUserMerchants(userId); }
    async getMerchantAccountById(merchantId: string) { return MerchantAccounts.getMerchantById(merchantId); }
    async updateMerchantSettlement(merchantId: string, data: any) { return MerchantAccounts.updateSettlementInfo(merchantId, data); }
    async getMerchantTransactions(userId: string, limit: number = 50, offset: number = 0) {
        const transactions = await ServiceActorOps.getMerchantTransactions(userId, limit, offset);
        if (transactions.length > 0) {
            return transactions;
        }
        const fallback = await this.ledger.getLatestTransactions(userId, limit, offset);
        return fallback.filter((tx: any) => {
            const metadata = tx?.metadata || {};
            return metadata.service_context === 'MERCHANT' || metadata.merchant_id;
        });
    }
    async getAgentTransactions(userId: string, limit: number = 50, offset: number = 0) {
        const transactions = await ServiceActorOps.getAgentTransactions(userId, limit, offset);
        if (transactions.length > 0) {
            return transactions;
        }
        const fallback = await this.ledger.getLatestTransactions(userId, limit, offset);
        return fallback.filter((tx: any) => {
            const metadata = tx?.metadata || {};
            return metadata.service_context === 'AGENT_CASH';
        });
    }
    async getMerchantWallets(userId: string) { return ServiceActorOps.getMerchantWallets(userId); }
    async getAgentWallets(userId: string) { return ServiceActorOps.getAgentWallets(userId); }
    async lookupAgentByCode(query: string) { return ServiceActorOps.lookupAgentByCode(query); }
    async registerCustomerByServiceActor(actor: any, actorRole: 'MERCHANT' | 'AGENT', payload: any) {
        return ServiceActorOps.registerCustomerByActor(actor, actorRole, payload, this.auth);
    }
    async getServiceLinkedCustomers(actorUserId?: string, actorRole?: string) {
        return ServiceActorOps.getLinkedCustomers(actorUserId, actorRole);
    }
    async getServiceCommissions(actorUserId?: string, actorRole?: string) {
        return ServiceActorOps.getServiceCommissions(actorUserId, actorRole);
    }
    async processMerchantPayment(payload: any, user: any) {
        return this.processSecurePayment({
            ...payload,
            type: payload.type || 'EXTERNAL_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'MERCHANT',
                merchant_actor_id: user?.id,
                merchant_role: user?.role || user?.user_metadata?.role || 'MERCHANT',
            },
        }, user);
    }
    async previewOrbiPayPayment(userId: string, payload: any) {
        return this.getTransactionPreview(userId, {
            ...payload,
            type: payload.type || 'MERCHANT_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'MERCHANT',
                payment_channel: payload.channel || 'ORBI_PAY',
                merchant_pay_number: payload.merchantPayNumber,
                merchant_reference: payload.reference,
                merchant_name: payload.merchantName,
            },
        });
    }
    async processOrbiPayPayment(payload: any, user: any) {
        return this.processSecurePayment({
            ...payload,
            type: payload.type || 'MERCHANT_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'MERCHANT',
                payment_channel: payload.channel || 'ORBI_PAY',
                merchant_pay_number: payload.merchantPayNumber,
                merchant_reference: payload.reference,
                merchant_name: payload.merchantName,
                initiated_by_consumer: true,
                payer_user_id: user?.id,
            },
        }, user);
    }
    async previewBillPayment(userId: string, payload: any) {
        return this.getTransactionPreview(userId, {
            ...payload,
            type: payload.type || 'BILL_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'BILL_PAYMENT',
                bill_provider: payload.provider,
                bill_category: payload.billCategory,
                bill_reference: payload.reference,
            },
        });
    }
    async processBillPayment(payload: any, user: any) {
        return this.processSecurePayment({
            ...payload,
            type: payload.type || 'BILL_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'BILL_PAYMENT',
                payment_channel: payload.channel || 'ORBI_BILL_PAY',
                bill_provider: payload.provider,
                bill_category: payload.billCategory,
                bill_reference: payload.reference,
                initiated_by_consumer: true,
                payer_user_id: user?.id,
            },
        }, user);
    }
    getBillPaymentProviders() {
        return [
            { key: 'electricity', label: 'Electricity', providers: ['TANESCO', 'ZESCO', 'LUKU'] },
            { key: 'school-fees', label: 'School fees', providers: ['Ada ya shule', 'Ada ya chuo', 'Hosteli'] },
            { key: 'water-bills', label: 'Water bills', providers: ['DAWASA', 'RUWASA', 'Maji ya mkoa'] },
            { key: 'gas', label: 'Gas', providers: ['Oryx Gas', 'Taifa Gas', 'Lake Gas'] },
            { key: 'bundles', label: 'Bundles', providers: ['Vodacom', 'Airtel', 'Tigo', 'Halotel'] },
            { key: 'entertainment', label: 'Entertainment', providers: ['DSTV', 'Azam TV', 'Startimes', 'Netflix'] },
        ];
    }
    async processAgentCashOperation(payload: any, user: any, direction: 'deposit' | 'withdrawal') {
        const normalizedType = direction === 'deposit' ? 'DEPOSIT' : 'WITHDRAWAL';
        return this.processSecurePayment({
            ...payload,
            type: normalizedType,
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'AGENT_CASH',
                cash_direction: direction,
                agent_actor_id: user?.id,
                agent_role: user?.role || user?.user_metadata?.role || 'AGENT',
            },
        }, user);
    }

    // --- FINANCIAL CORE ENGINE (MULTI-TENANT) ---
    async createTenant(userId: string, data: any) { return FinancialCore.createTenant(userId, data); }
    async getUserTenants(userId: string) { return FinancialCore.getUserTenants(userId); }
    async generateTenantApiKeys(userId: string, tenantId: string, type?: 'test' | 'live') { return FinancialCore.generateApiKeys(userId, tenantId, type); }
    async getTenantApiKeys(userId: string, tenantId: string) { return FinancialCore.getApiKeys(userId, tenantId); }
    async revokeTenantApiKey(userId: string, tenantId: string, keyId: string) { return FinancialCore.revokeApiKey(userId, tenantId, keyId); }
    async getTenantWallets(userId: string, tenantId: string) { return FinancialCore.getTenantWallets(userId, tenantId); }

    // --- SETTLEMENT ENGINE ---
    async getTenantSettlementConfig(userId: string, tenantId: string) { return SettlementEngine.getSettlementConfig(userId, tenantId); }
    async updateTenantSettlementConfig(userId: string, tenantId: string, config: any) { return SettlementEngine.updateSettlementConfig(userId, tenantId, config); }
    async getTenantPendingSettlement(tenantId: string) { return SettlementEngine.calculatePendingSettlement(tenantId); }
    async triggerTenantPayout(userId: string, tenantId: string) { return SettlementEngine.triggerPayout(userId, tenantId); }
    async getTenantPayoutHistory(userId: string, tenantId: string) { return SettlementEngine.getPayoutHistory(userId, tenantId); }

    async registerMerchant(payload: any) { return RegulatoryService.registerMerchant(payload); }

    async getPartners() { return PartnerRegistry.listPartners(); }
    async registerPartner(payload: any, actorId: string) {
        return PartnerRegistry.addPartner({
            ...payload,
            provider_metadata: payload.provider_metadata || payload.metadata || {},
            connection_secret:
                payload.connection_secret ||
                payload.client_secret ||
                payload.connection ||
                '',
            logic_type: payload.logic_type || 'REGISTRY',
        });
    }

    async getInstitutionalPaymentAccounts(filters?: any) {
        return institutionalFundsService.listInstitutionalAccounts(filters);
    }

    async getPlatformFeeConfigs(filters?: any) {
        return platformFeeService.listConfigs(filters);
    }

    async upsertPlatformFeeConfig(payload: any, actorId: string, configId?: string) {
        return platformFeeService.upsertConfig(payload, actorId, configId);
    }

    async upsertInstitutionalPaymentAccount(payload: any, actorId: string, accountId?: string) {
        return institutionalFundsService.upsertInstitutionalAccount(payload, actorId, accountId);
    }

    async previewExternalFundMovement(userId: string, payload: any) {
        return institutionalFundsService.previewMovement(userId, payload);
    }

    async createIncomingDepositIntent(userId: string, payload: any) {
        return institutionalFundsService.createIncomingDepositIntent(userId, payload);
    }

    async processExternalFundMovement(userId: string, payload: any) {
        return institutionalFundsService.processMovement(userId, payload);
    }

    async getUserExternalFundMovements(userId: string, limit?: number, offset?: number) {
        return institutionalFundsService.listMovements(userId, limit, offset);
    }

    async getUserExternalFundMovementById(userId: string, movementId: string) {
        return institutionalFundsService.getMovementById(userId, movementId);
    }

    async processOfflineGatewayRequest(payload: any) {
        return offlineGatewayService.handleInboundRequest(payload);
    }

    async processOfflineGatewayConfirmation(payload: any) {
        return offlineGatewayService.handleConfirmation(payload);
    }

    // --- DATA & MESSAGING ---
    async updateUserProfile(userId: string, updates: any, currentMetadata: any) {
        const safeUpdates = updates && typeof updates === 'object' ? updates : {};
        const safeCurrentMetadata =
            currentMetadata && typeof currentMetadata === 'object' ? currentMetadata : {};
        const isVerified = safeCurrentMetadata?.kyc_status === 'verified';
        
        // Define allowed fields based on status
        // Verified: Only avatar and settings (identity is locked)
        // Unverified: full_name, phone, address, nationality, avatar_url, metadata, currency, and settings
        const settingsFields = [
            'language', 'notif_push', 'notif_email', 'notif_security', 'notif_financial', 'notif_budget', 'notif_marketing',
            'security_tx_pin_hash', 'security_tx_pin_enabled', 'security_biometric_enabled', 'fcm_token'
        ];

        const allowedFields = isVerified 
            ? ['avatar_url', 'avatar', ...settingsFields] 
            : ['full_name', 'phone', 'address', 'nationality', 'avatar_url', 'metadata', 'currency', ...settingsFields];

        const attemptedFields = Object.keys(safeUpdates);
        const forbiddenFields = attemptedFields.filter(f => !allowedFields.includes(f));
        
        if (forbiddenFields.length > 0) {
            return { 
                error: `SECURITY_RESTRICTION: You cannot update the following fields: ${forbiddenFields.join(', ')}. ${isVerified ? 'Verified accounts are locked.' : ''}` 
            };
        }

        const sb = getSupabase();
        const adminSb = getAdminSupabase();
        
        if (!sb || !adminSb) {
            return { error: 'DB_CONNECTION_ERROR: Database service unavailable.' };
        }

        try {
            // 1. Update Auth Metadata (for fields that live there)
            // We must merge with current metadata to avoid losing fields like role, registry_type, etc.
            const metadataUpdates: any = { ...safeCurrentMetadata };
            if (safeUpdates.full_name) metadataUpdates.full_name = safeUpdates.full_name;
            if (safeUpdates.phone) metadataUpdates.phone = safeUpdates.phone;
            if (safeUpdates.nationality) metadataUpdates.nationality = safeUpdates.nationality;
            if (safeUpdates.address) metadataUpdates.address = safeUpdates.address;
            if (safeUpdates.avatar_url) metadataUpdates.avatar_url = safeUpdates.avatar_url;
            if (safeUpdates.currency) metadataUpdates.currency = safeUpdates.currency;
            if (safeUpdates.language) metadataUpdates.language = safeUpdates.language;
            
            // Sync settings to metadata for immediate access in auth-based logic
            settingsFields.forEach(field => {
                if (safeUpdates[field] !== undefined) metadataUpdates[field] = safeUpdates[field];
            });

            if (safeUpdates.metadata && typeof safeUpdates.metadata === 'object') {
                Object.assign(metadataUpdates, safeUpdates.metadata);
            }

            if (Object.keys(metadataUpdates).length > 0) {
                const { error } = await adminSb.auth.admin.updateUserById(userId, { user_metadata: metadataUpdates });
                if (error) throw error;
            }
            
            // 2. Update Public Tables (users/staff)
            const tableUpdates = { ...safeUpdates };
            delete tableUpdates.metadata; 
            delete tableUpdates.avatar; 

            if (Object.keys(tableUpdates).length > 0) {
                // Use admin client to ensure update succeeds regardless of RLS (server-side authoritative update)
                const { error: userError } = await adminSb.from('users').update(tableUpdates).eq('id', userId);
                if (userError) console.warn(`[UserProfile] User table update warning: ${userError.message}`);
                
                // Try updating 'staff' table (if user is staff)
                if (safeCurrentMetadata?.registry_type === 'STAFF') {
                    const { error: staffError } = await adminSb.from('staff').update(tableUpdates).eq('id', userId);
                    if (staffError) console.warn(`[UserProfile] Staff table update warning: ${staffError.message}`);
                }
            }
            
            await this.security.logActivity(userId, 'PROFILE_UPDATE', 'success', `Updated fields: ${attemptedFields.join(', ')}`);
            return { success: true };
        } catch (e: any) {
            console.error(`[UserProfile] Update failed: ${e.message}`);
            return { error: `UPDATE_FAILED: ${e.message}` };
        }
    }

    async updateLoginInfo(userId: string, email?: string, password?: string) {
        const sb = getSupabase();
        const adminSb = getAdminSupabase();
        
        if (!sb || !adminSb) return { error: 'DB_OFFLINE' };

        const updates: any = {};
        if (email) updates.email = email;
        if (password) updates.password = password;

        if (Object.keys(updates).length === 0) return { error: 'NO_CHANGES_REQUESTED' };

        // Use Admin API to update without requiring old password (assuming session authentication is sufficient for this scope)
        // In a stricter environment, we would require old_password verification before calling this.
        const { error } = await adminSb.auth.admin.updateUserById(userId, updates);
        
        if (error) return { error: error.message };

        // If email changed, we should probably update the public users table too
        if (email) {
            await sb.from('users').update({ email }).eq('id', userId);
            await sb.from('staff').update({ email }).eq('id', userId);
        }

        await this.security.logActivity(userId, 'LOGIN_INFO_UPDATE', 'success', `Updated login info: ${Object.keys(updates).join(', ')}`);
        return { success: true };
    }

    async uploadAvatar(userId: string, file: any, contentType?: string, oldUrl?: string) {
        if (oldUrl) await AssetLifecycle.decommission(oldUrl, userId);
        const avatarUrl = await AssetLifecycle.commit(userId, file, contentType);
        if (!avatarUrl) return avatarUrl;

        const adminSb = getAdminSupabase();
        if (!adminSb) {
            throw new Error('DB_OFFLINE');
        }

        const { data: authUserResult, error: authUserError } = await adminSb.auth.admin.getUserById(userId);
        if (authUserError) {
            throw new Error(authUserError.message);
        }

        const currentMetadata = authUserResult?.user?.user_metadata || {};
        const metadataUpdates = {
            ...currentMetadata,
            avatar_url: avatarUrl,
        };

        const { error: authUpdateError } = await adminSb.auth.admin.updateUserById(userId, {
            user_metadata: metadataUpdates,
        });
        if (authUpdateError) {
            throw new Error(authUpdateError.message);
        }

        const profileUpdate = { avatar_url: avatarUrl };
        const { error: userUpdateError } = await adminSb.from('users').update(profileUpdate).eq('id', userId);
        if (userUpdateError) {
            console.warn(`[Avatar] users update warning: ${userUpdateError.message}`);
        }

        const registryType = String(currentMetadata?.registry_type || '').toUpperCase();
        if (registryType === 'STAFF') {
            const { error: staffUpdateError } = await adminSb.from('staff').update(profileUpdate).eq('id', userId);
            if (staffUpdateError) {
                console.warn(`[Avatar] staff update warning: ${staffUpdateError.message}`);
            }
        }

        return avatarUrl;
    }
    async getUserMessages(userId: string, limit: number = 50, offset: number = 0): Promise<UserMessage[]> {
        return Messaging.getMessages(userId, limit, offset);
    }
    async getSystemMessages(): Promise<SystemMessage[]> {
        return []; 
    }
    async markMessageRead(userId: string, id: string) {
        return Messaging.markAsRead(userId, id);
    }
    async markAllMessagesRead(userId: string) { 
        return Messaging.markAllAsRead(userId);
    }
    async deleteMessage(userId: string, id: string) {
        return Messaging.deleteMessage(userId, id);
    }
    async getSecurityPulse() { return Sentinel.inspectOperation(null, 'PULSE_CHECK', {}); }
    async getAnomalyReport(days: number = 7) { return ProviderAnomalyTracker.generateReport(days); }

    // --- AUDIT & SECURITY LOGS ---
    async getAuditTrail() { return Audit.getLogs(); }
    async getGlobalAuditLogs() { return Audit.getLogs(); }
    async getAllTransactions(filters?: {
        limit?: number;
        offset?: number;
        status?: string;
        type?: string;
        currency?: string;
        query?: string;
        dateFrom?: string;
        dateTo?: string;
    }) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const limit = Number(filters?.limit ?? 100);
        const offset = Number(filters?.offset ?? 0);

        let query = sb
            .from('transactions')
            .select('*', { count: 'exact' })
            .order('date', { ascending: false })
            .range(offset, offset + Math.max(limit, 1) - 1);

        if (filters?.status) query = query.eq('status', String(filters.status));
        if (filters?.type) query = query.eq('type', String(filters.type));
        if (filters?.currency) query = query.eq('currency', String(filters.currency).toUpperCase());
        if (filters?.dateFrom) query = query.gte('date', filters.dateFrom);
        if (filters?.dateTo) query = query.lte('date', filters.dateTo);
        if (filters?.query) {
            const q = String(filters.query).trim();
            query = query.or(buildPostgrestOrFilter([
                { column: 'reference_id', operator: 'ilike', value: q },
                { column: 'description', operator: 'ilike', value: q },
                { column: 'status', operator: 'ilike', value: q },
                { column: 'type', operator: 'ilike', value: q },
            ]));
        }

        const { data, error, count } = await query;
        if (error) throw new Error(error.message);

        return {
            items: data || [],
            total: count || 0,
        };
    }

    async getTransactionVolumeSummary(filters?: {
        status?: string;
        type?: string;
        currency?: string;
        query?: string;
        dateFrom?: string;
        dateTo?: string;
    }) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        let query = sb
            .from('transactions')
            .select('id, amount, currency, status, type, date');

        if (filters?.status) query = query.eq('status', String(filters.status));
        if (filters?.type) query = query.eq('type', String(filters.type));
        if (filters?.currency) query = query.eq('currency', String(filters.currency).toUpperCase());
        if (filters?.dateFrom) query = query.gte('date', filters.dateFrom);
        if (filters?.dateTo) query = query.lte('date', filters.dateTo);
        if (filters?.query) {
            const q = String(filters.query).trim();
            query = query.or(buildPostgrestOrFilter([
                { column: 'reference_id', operator: 'ilike', value: q },
                { column: 'description', operator: 'ilike', value: q },
                { column: 'status', operator: 'ilike', value: q },
                { column: 'type', operator: 'ilike', value: q },
            ]));
        }

        const { data, error } = await query;
        if (error) throw new Error(error.message);

        const rows = data || [];
        const totalByCurrency: Record<string, number> = {};
        const completedByCurrency: Record<string, number> = {};
        let count = 0;
        let completedCount = 0;
        let totalAmountBase = 0;

        for (const tx of rows as any[]) {
            const amount = Number(tx.amount || 0);
            if (!Number.isFinite(amount)) continue;
            const currency = String(tx.currency || 'TZS').toUpperCase();
            totalByCurrency[currency] = (totalByCurrency[currency] || 0) + amount;
            totalAmountBase += amount;
            count += 1;

            if (String(tx.status || '').toLowerCase() === 'completed') {
                completedByCurrency[currency] = (completedByCurrency[currency] || 0) + amount;
                completedCount += 1;
            }
        }

        return {
            count,
            completedCount,
            totalByCurrency,
            completedByCurrency,
            averageTicket: count ? totalAmountBase / count : 0,
        };
    }
    async getLedgerEntries(transactionId: string) { return this.ledger.getLedgerEntries(transactionId); }
    async getUserActivity(token?: string) {
        const session = await this.auth.getSession(token);
        if (!session) return [];
        return this.security.getUserActivity(session.sub);
    }
    async logActivity(userId: string, type: string, status: string, details: string, fingerprint?: string) {
        return this.security.logActivity(userId, type, status, details, undefined, fingerprint);
    }
    async approveTransaction(txId: string, notes: string) { return this.ledger.updateTransactionStatus(txId, 'completed', notes); }
    async rejectTransaction(txId: string, notes: string) { return this.ledger.updateTransactionStatus(txId, 'failed', notes); }
    async getTransactionLimits() { return ConfigClient.getRuleConfig(); }
    async rotateTransactionLimits(newLimits: any) { return ConfigClient.saveConfig(newLimits); }

    // --- STAFF MESSAGING (Nexus Chat) ---
    async sendStaffMessage(content: string, options: any) {
        const sb = getSupabase();
        if (!sb) return;
        const { data: { session } } = await sb.auth.getSession();
        if (!session) return;
        
        await sb.from('staff_messages').insert({
            sender_id: session.user.id,
            sender_name: session.user.user_metadata?.full_name || 'Staff Node',
            content,
            type: 'staff',
            target_role: options.targetRole,
            recipient_id: options.recipientId,
            created_at: new Date().toISOString()
        });
    }
    async getStaffChatHistory() {
        const sb = getSupabase();
        if (!sb) return [];
        const { data } = await sb.from('staff_messages').select('*').order('created_at', { ascending: true });
        return data || [];
    }
    async flagStaffMessage(messageId: string) {
        const sb = getSupabase();
        if (sb) await sb.from('staff_messages').update({ is_flagged: true }).eq('id', messageId);
    }
    async purgeStaffChatHistory(actorId: string) {
        const sb = getSupabase();
        if (sb) await sb.from('staff_messages').delete().neq('id', '0'); 
    }

    public calculateOverview(transactions: Transaction[], wallets: Wallet[], goals: Goal[]): FinancialOverview {
        return FinancialLogic.calculateOverview(transactions, wallets, goals);
    }

    // --- ENTERPRISE B2B & TREASURY ---
    async createOrganization(payload: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        
        // 1. Create the Organization
        const baseCurrency = typeof payload?.base_currency === 'string'
            ? payload.base_currency.trim().toUpperCase()
            : '';
        if (!baseCurrency) {
            throw new Error("CURRENCY_REQUIRED: Organization base currency is required.");
        }

        const { data, error } = await sb.from('organizations').insert({
            name: payload.name,
            registration_number: payload.registration_number,
            tax_id: payload.tax_id,
            country: payload.country,
            base_currency: baseCurrency,
            metadata: payload.metadata || {}
        }).select().single();

        if (error) return { error: error.message };

        // 2. Auto-assign the creator as the Organization ADMIN
        await sb.from('users').update({ 
            organization_id: data.id, 
            org_role: 'ADMIN' 
        }).eq('id', actorId);

        await this.security.logActivity(actorId, 'ORG_CREATED', 'success', `Created organization ${payload.name} and assumed ADMIN role`);
        return { success: true, data };
    }

    async getOrganizations(userId: string) {
        const sb = getAdminSupabase();
        if (!sb) return [];
        const { data } = await sb.from('users').select('organization_id, organizations(*)').eq('id', userId).single();
        if (!data || !data.organization_id) return [];
        return [data.organizations];
    }

    async linkUserToOrganization(userId: string, orgId: string, role: string, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        // 1. Security Check: Ensure the actor is an ADMIN of this specific organization
        const { data: actor } = await sb.from('users').select('organization_id, org_role').eq('id', actorId).single();
        if (!actor || actor.organization_id !== orgId || actor.org_role !== 'ADMIN') {
            return { error: 'UNAUTHORIZED: Only Organization Admins can manage team members.' };
        }

        // 2. Link the user and assign the role
        const { error } = await sb.from('users').update({
            organization_id: orgId,
            org_role: role
        }).eq('id', userId);

        if (error) return { error: error.message };
        await this.security.logActivity(actorId, 'USER_ORG_LINKED', 'success', `Linked user ${userId} to org ${orgId} as ${role}`);
        return { success: true };
    }

    async inviteUserByEmail(email: string, orgId: string, role: string, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        // 1. Security Check: Ensure the actor is an ADMIN of this specific organization
        const { data: actor } = await sb.from('users').select('organization_id, org_role, organizations(name)').eq('id', actorId).single();
        if (!actor || actor.organization_id !== orgId || actor.org_role !== 'ADMIN') {
            return { error: 'UNAUTHORIZED: Only Organization Admins can invite team members.' };
        }

        // 2. Find the user by email
        const { data: targetUser } = await sb.from('users').select('id, full_name').eq('email', email).single();
        if (!targetUser) {
            return { error: 'USER_NOT_FOUND: No Orbi account found with this email. They must register first.' };
        }

        // 3. Link the user
        const { error } = await sb.from('users').update({
            organization_id: orgId,
            org_role: role
        }).eq('id', targetUser.id);

        if (error) return { error: error.message };
        
        // 4. Send Real-Time Push Notification to the invited user
        const orgName = (actor.organizations as any)?.name || 'an organization';
        await Messaging.dispatch(
            targetUser.id,
            'info',
            'You have been added to an Organization',
            `You have been invited to join ${orgName} as a ${role}. Your corporate wallet is now active.`,
            { 
                sms: true,
                email: true,
                template: 'Org_Invitation',
                variables: { orgName, role }
            }
        );

        await this.security.logActivity(actorId, 'USER_ORG_INVITED', 'success', `Invited user ${email} to org ${orgId} as ${role}`);
        return { success: true, userId: targetUser.id };
    }

    async requestTreasuryWithdrawal(userId: string, goalId: string, amount: number, destinationWalletId: string, reason: string) {
        try {
            const txId = await Treasury.requestWithdrawal(userId, goalId, amount, destinationWalletId, reason);
            return { success: true, txId };
        } catch (e: any) {
            return { error: e.message };
        }
    }

    async approveTreasuryWithdrawal(adminId: string, txId: string) {
        const isFullyApproved = await Treasury.approveWithdrawal(adminId, txId);
        return { isFullyApproved };
    }

    async getOrganizationDetails(orgId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        
        const { data: org } = await sb.from('organizations').select('*').eq('id', orgId).single();
        if (!org) return { error: 'NOT_FOUND' };

        const { data: members } = await sb.from('users').select('id, full_name, email, org_role, account_status').eq('organization_id', orgId);
        const { data: goals } = await sb.from('goals').select('*').eq('organization_id', orgId).eq('is_corporate', true);
        
        return { success: true, data: { ...org, members: members || [], goals: goals || [] } };
    }

    async getPendingApprovals(orgId: string) {
        const data = await Treasury.getPendingApprovals(orgId);
        return { success: true, data };
    }

    async configureAutoSweep(goalId: string, enabled: boolean, threshold: number) {
        const success = await Treasury.configureAutoSweep(goalId, enabled, threshold);
        return { success };
    }

    async getBudgetAlerts(orgId: string, limit: number = 50) {
        const sb = getAdminSupabase();
        if (!sb) return [];
        const { data } = await sb.from('budget_alerts')
            .select('*, categories(name, currency), users(full_name)')
            .eq('organization_id', orgId)
            .order('created_at', { ascending: false })
            .limit(limit);
        return data || [];
    }

    // --- RECONCILIATION ENGINE ---
    async runFullReconciliation() {
        return ReconEngine.runAllRecon();
    }

    async getReconciliationReports(limit: number = 50) {
        const sb = getAdminSupabase();
        if (!sb) return [];
        const { data } = await sb.from('reconciliation_reports')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(limit);
        return data || [];
    }
}

export const Server = new OrbiServer();
