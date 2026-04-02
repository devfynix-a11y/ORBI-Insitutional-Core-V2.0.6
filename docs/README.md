
# ORBI Sovereign Backend Node (v31.0 Titanium)

This is the **Sovereign Financial Operating System** powering the ORBI ecosystem. It is a headless, banking-grade API node designed to power mobile and desktop financial applications with zero-trust security and atomic ledger integrity.

## 📚 Documentation

*   **[Deployment Guide](./DEPLOYMENT_GUIDE.md)**: Steps to deploy on Render.
*   **[Project Structure](./PROJECT_STRUCTURE.md)**: Breakdown of file locations and functions.
*   **[Financial Core Engine (Core Banking Architecture)](./CORE_BANKING_ARCHITECTURE.md)**: **NEW** - Multi-Tenant Fintech Platform, Banking-as-a-Service (BaaS).
*   **[Enterprise B2B Architecture](./ENTERPRISE_B2B_ARCHITECTURE.md)**: Multi-Tenancy, Corporate Goals, and Hard Budgets.
*   **[Multi-Tenant Merchant Architecture](./MERCHANT_ARCHITECTURE.md)**: Marketplaces, Payment Gateways, and Business Accounts.
*   **[Reconciliation Engine](./RECONCILIATION_ENGINE.md)**: Financial Integrity & Forensic Auditing.
*   **[Production Deployment](./PRODUCTION_DEPLOYMENT.md)**: Production readiness checks, env requirements, and rollout guidance.
*   **[Master Integration Manual](./INTEGRATION_MANUAL.md)**: The definitive technical specification.
*   **[Provider Registry Contract](./PROVIDER_REGISTRY_CONTRACT.md)**: Admin/UI and backend contract for registry-driven providers.
*   **[Universal Provider And Offline Gateway Status](./UNIVERSAL_PROVIDER_AND_OFFLINE_GATEWAY_STATUS.md)**: Current implementation status for routing, institutional settlements, deposit intents, and offline bridge flows.
*   **[Agent, Merchant, and System Fee Flows](./AGENT_MERCHANT_FEE_FLOWS.md)**: How fees and commissions use `platform_fee_configs`.
*   **[Mobile SDK Guide](./MOBILE_SDK_GUIDE.md)**: For iOS/Android developers.
*   **[Quick Start Guide](./INTEGRATION_GUIDE.md)**: Get connected in 5 minutes.
*   **[Vision & Philosophy](./manual.md)**: The "Why" behind ORBI.

## 🚀 Core Features
- **Orbi TrustBridge (Secure Escrow)**: Conditional payment system with PaySafe locking, multi-party release, and AI-assisted dispute resolution.
- **Enterprise Treasury Automation**: Multi-Sig withdrawal flows, automated treasury auto-sweep, and departmental budget enforcement.
- **Neural Sentinel AI (Security)**: Real-time behavioral risk analysis and fraud prevention for every ingress operation (<50ms latency).
- **Next-Generation Security Architecture (9-Layer)**: True Zero-Trust model featuring Passkeys (FIDO2), Device Fingerprinting, Behavioral Biometrics, AI Fraud Detection, and Hardware Security Module (HSM) integration.
- **Financial Core Engine (Core Banking)**: True Multi-Tenant Architecture (Individuals, Merchants, Marketplaces, Partners) with strict Row Level Security (RLS) isolation.
- **Enterprise B2B Multi-Tenancy**: Corporate Treasury Goals, Departmental Cost Centers, and Hard Budget Enforcement.
- **Multi-Tenant Merchant Architecture**: Users can own and manage multiple merchant accounts with dedicated wallets, settlement schedules, and fee configurations.
- **Transaction State Machine**: Strict lifecycle management (Created -> Authorized -> Settled -> Completed) with forensic auditability.
- **Reconciliation Engine**: Continuous multi-layer verification (Internal, System, External) to ensure absolute ledger integrity.
- **Atomic Multi-Leg Ledger**: Ensures fiscal integrity for every asset migration (Principal + Tax + Fee + Yield). Includes `append_ledger_entries_v1` for high-performance, atomic ledger updates.
- **Multi-Currency & FX Engine**: Real-time currency conversion with live exchange rates, 0.5% conversion fees, and USD normalization.
- **Risk & Compliance Engine (AML)**: Advanced transaction monitoring, velocity checks, structuring detection, and high-risk jurisdiction flagging.
- **Continuous Session Monitoring**: Real-time invalidation of compromised sessions based on IP or device fingerprint changes.
- **Transaction Guard (Policy Engine)**: Financial rule enforcement and limit management (`/backend/ledger/PolicyEngine.ts`).
- **Content Sanitization**: Deep XSS protection for all JSON payloads (`/backend/security/sanitizer.ts`).
- **Cyber Sentinel AI**: Neural behavioral risk analysis for every ingress operation (<50ms latency).
- **Zero-Trust Identity**: Dynamic Identity Quarantine (DIQ) for all new nodes.
- **Intelligent Messaging & Monitoring**: Multi-channel router with direct-to-app WebSocket delivery, automated fallbacks (SMS, Push, WhatsApp, Email), and real-time operational alerting for system administrators. Includes unique transactional reference numbers (`refId`) and device identification for enhanced security context.
- **Real-Time Nexus**: High-throughput WebSocket stream for instant balance updates and direct-to-app notifications.
- **Email Notifications**: Integrated SMTP service for transactional emails and alerts.
- **Robust API Error Handling**: Comprehensive `try-catch` boundaries across all v1 and admin routes, ensuring graceful degradation and consistent error payloads.
- **Transaction Service (V2.0)**: Enhanced financial integrity with proactive balance verification, system-wide reconciliation, and forensic reversal capabilities.

##  Deployment
This node is optimized for **Render**. Ensure the environment variables defined in `render.yaml` are configured in your dashboard.

## 🏢 Enterprise Readiness
The ORBI Sovereign Backend is a professional, enterprise-grade financial infrastructure designed for high-stakes operations. It features:
- **Modular, Service-Oriented Architecture**: Clean separation of concerns across specialized domains (Ledger, Security, Payments, Enterprise, IAM).
- **Security-First Design**: Multi-layered defense including HSM integration, WAF, KMS, and real-time fraud detection.
- **Resilience and Scalability**: Built for distributed environments with Redis-backed event buses, lock management, and failure recovery engines.
- **Financial Integrity and Compliance**: Atomic ledger operations, continuous reconciliation, and immutable audit trails.
- **Enterprise B2B Capabilities**: Support for complex business relationships, treasury management, and hard budget enforcement.
