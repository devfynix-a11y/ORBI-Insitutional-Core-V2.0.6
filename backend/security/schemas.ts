
import { z } from 'zod';

/**
 * ORBI VALIDATION SCHEMAS (V1.0)
 * Centralized Zod schemas for API request validation.
 */

export const LoginSchema = z.object({
    e: z.string().optional(),
    p: z.string().min(8, "Password must be at least 8 characters").optional(),
    email: z.string().optional(),
    password: z.string().min(8, "Password must be at least 8 characters").optional()
}).refine(data => (data.e && data.p) || (data.email && data.password), {
    message: "Must provide either (email, password) or (e, p)"
});

export const SignUpSchema = z.object({
    e: z.string().optional(),
    p: z.string().min(8).optional(),
    email: z.string().optional(),
    password: z.string().min(8).optional(),
    full_name: z.string().min(1),
    phone: z.string().min(1).optional(),
    nationality: z.string().optional(),
    address: z.string().optional(),
    language: z.enum(['en', 'sw']).optional(),
    currency: z.string().length(3).default('USD'),
    registry_type: z.string().default('CONSUMER'),
    metadata: z.record(z.string(), z.any()).optional()
}).refine(data => (data.email || data.e) || data.phone, {
    message: "Must provide either email or phone"
}).refine(data => (data.password || data.p), {
    message: "Password is required"
});

export const PaymentIntentSchema = z.object({
    sourceWalletId: z.string().uuid().optional(),
    targetWalletId: z.string().uuid().optional(),
    recipientId: z.string().optional(),
    recipient_customer_id: z.string().optional(),
    amount: z.number().positive(),
    currency: z.string().length(3),
    description: z.string().max(255),
    type: z.enum(['INTERNAL_TRANSFER', 'EXTERNAL_PAYMENT', 'BILL_PAYMENT', 'PEER_TRANSFER', 'DEPOSIT', 'WITHDRAWAL']),
    metadata: z.record(z.string(), z.any()).optional(),
    categoryId: z.union([z.string(), z.number()]).optional(),
    dryRun: z.boolean().optional()
});

export const WalletCreateSchema = z.object({
    name: z.string().min(1),
    currency: z.string().length(3).default('USD'),
    color: z.string().optional(),
    icon: z.string().optional(),
    type: z.string().optional(),
    metadata: z.record(z.string(), z.any()).optional()
});

export const WalletLockSchema = z.object({
    reason: z.string().max(255).optional(),
    pin: z.string().min(4).max(8).optional(),
    force: z.boolean().optional()
});

export const WalletUnlockSchema = z.object({
    pin: z.string().min(4).max(8).optional(),
    force: z.boolean().optional()
});

export const GoalCreateSchema = z.object({
    name: z.string().min(1),
    target: z.number().positive(),
    deadline: z.string().datetime().optional(),
    color: z.string().optional(),
    icon: z.string().optional(),
    fundingStrategy: z.enum(['manual', 'percentage', 'fixed']).optional(),
    autoAllocationEnabled: z.boolean().optional(),
    linkedIncomePercentage: z.number().optional(),
    monthlyTarget: z.number().optional()
});

export const GoalUpdateSchema = z.object({
    name: z.string().min(1).optional(),
    target: z.number().positive().optional(),
    deadline: z.string().datetime().nullable().optional(),
    color: z.string().optional(),
    icon: z.string().optional(),
    fundingStrategy: z.enum(['manual', 'percentage', 'fixed']).optional(),
    autoAllocationEnabled: z.boolean().optional(),
    linkedIncomePercentage: z.number().optional(),
    monthlyTarget: z.number().optional()
}).refine(data => Object.keys(data).length > 0, {
    message: 'At least one goal field is required'
});

export const KYCSubmitSchema = z.object({
    full_name: z.string().min(1),
    id_type: z.enum(['NATIONAL_ID', 'DRIVER_LICENSE', 'VOTER_ID', 'PASSPORT']),
    id_number: z.string().min(5),
    document_url: z.string().url(),
    selfie_url: z.string().url(),
    metadata: z.record(z.string(), z.any()).optional()
});

export const KYCReviewSchema = z.object({
    requestId: z.string().uuid(),
    decision: z.enum(['APPROVED', 'REJECTED']),
    reason: z.string().optional()
});

export const AccountStatusUpdateSchema = z.object({
    status: z.enum(['active', 'blocked', 'frozen', 'pending'])
});

export const UserProfileUpdateSchema = z.object({
    full_name: z.string().optional(),
    phone: z.string().optional(),
    address: z.string().optional(),
    nationality: z.string().optional(),
    kyc_level: z.number().optional(),
    kyc_status: z.enum(['unverified', 'pending', 'verified', 'rejected']).optional(),
    language: z.enum(['en', 'sw']).optional(),
    notif_security: z.boolean().optional(),
    notif_financial: z.boolean().optional(),
    notif_budget: z.boolean().optional(),
    notif_marketing: z.boolean().optional(),
    security_tx_pin_hash: z.string().optional(),
    security_tx_pin_enabled: z.boolean().optional(),
    security_biometric_enabled: z.boolean().optional(),
    avatar_url: z.string().optional(),
    currency: z.string().length(3).optional()
});

export const StaffCreateSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
    full_name: z.string().min(1),
    role: z.enum(['SUPER_ADMIN', 'ADMIN', 'IT', 'AUDIT', 'ACCOUNTANT', 'CUSTOMER_CARE', 'HUMAN_RESOURCE']),
    phone: z.string().optional(),
    nationality: z.string().optional(),
    address: z.string().optional()
});

export const ManagedIdentityCreateSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
    full_name: z.string().min(1),
    role: z.enum([
        'SUPER_ADMIN',
        'ADMIN',
        'IT',
        'AUDIT',
        'ACCOUNTANT',
        'CUSTOMER_CARE',
        'HUMAN_RESOURCE',
        'CONSUMER',
        'USER',
        'MERCHANT',
        'AGENT',
    ]),
    phone: z.string().optional(),
    nationality: z.string().optional(),
    address: z.string().optional(),
    currency: z.string().length(3).optional(),
    language: z.enum(['en', 'sw']).optional()
});

export const ServiceCustomerRegistrationSchema = z.object({
    email: z.string().email().optional(),
    phone: z.string().min(1).optional(),
    password: z.string().min(8),
    full_name: z.string().min(1),
    nationality: z.string().optional(),
    address: z.string().optional(),
    currency: z.string().length(3).optional(),
    language: z.enum(['en', 'sw']).optional()
}).refine(data => data.email || data.phone, {
    message: 'Must provide either email or phone'
});

export const ServiceAccessRequestCreateSchema = z.object({
    requested_role: z.enum(['MERCHANT', 'AGENT']),
    business_name: z.string().min(1).max(120).optional(),
    note: z.string().min(3).max(1000).optional(),
    phone: z.string().min(1).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
});

export const ServiceAccessRequestReviewSchema = z.object({
    decision: z.enum(['APPROVED', 'REJECTED']),
    review_note: z.string().max(1000).optional(),
});

export const BootstrapAdminSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
    full_name: z.string().min(1),
    phone: z.string().optional(),
    nationality: z.string().optional(),
    address: z.string().optional()
});

export const DeviceRegisterSchema = z.object({
    device_fingerprint: z.string().min(1),
    device_name: z.string().optional(),
    device_type: z.enum(['mobile', 'desktop', 'tablet']).optional(),
    user_agent: z.string().optional()
});

export const DeviceTrustSchema = z.object({
    is_trusted: z.boolean(),
    status: z.enum(['active', 'blocked', 'pending_approval']).optional()
});

export const DocumentUploadSchema = z.object({
    document_type: z.enum(['passport', 'utility_bill', 'contract', 'tax_form', 'other']),
    file_url: z.string().url(),
    file_name: z.string().optional(),
    mime_type: z.string().optional(),
    size_bytes: z.number().optional(),
    metadata: z.record(z.string(), z.any()).optional()
});

export const DocumentVerifySchema = z.object({
    status: z.enum(['verified', 'rejected', 'archived']),
    rejection_reason: z.string().optional()
});

