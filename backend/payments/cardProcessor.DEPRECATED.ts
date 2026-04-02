/**
 * DEPRECATED - DO NOT USE
 * =======================
 * This file has been replaced by the dynamic provider registry system.
 * 
 * SEE: GenericRestProvider.ts (registry-driven provider execution)
 * SEE: ProviderFactory.ts (runtime provider resolution)
 * SEE: cardRoutes.ts (API endpoints)
 * 
 * The card payment processor is now registered in the Admin UI provider registry
 * just like other payment providers.
 * 
 * No manual provider modules are needed - all configuration is done through:
 * 1. Admin UI: /api/admin/partners (provider registry management)
 * 2. Dynamic Gateway Router: gatewayRouter.registerGateway()
 * 3. Runtime: All payments route through gatewayRouter
 * 
 * MIGRATION GUIDE:
 * ===============
 * 
 * OLD (Standalone):
 *   import { cardProcessor } from './cardProcessor.ts';
 *   const token = await cardProcessor.tokenizeCard(userId, cardData);
 * 
 * NEW (Registry Runtime):
 *   // Provider execution is resolved at runtime from financial_partners
 *   // through ProviderFactory -> GenericRestProvider.
 *
 *   // All providers route through gateway:
 *   const gateway = gatewayRouter.getGateway('CARD');
 *   const auth = await gateway.authorizePayment(initiation);
 *   const settlement = await gateway.settlePayment(txId, walletId);
 */

export const DEPRECATED = true;
