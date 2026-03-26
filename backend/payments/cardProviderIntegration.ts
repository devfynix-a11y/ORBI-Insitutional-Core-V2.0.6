/**
 * APP INTEGRATION - CARD PROVIDER
 * ==============================
 * Card provider is registered through the dynamic ProviderFactory
 * Run this in your Express app initialization during startup
 * 
 * ARCHITECTURE: Preview Stable v2.0.4
 * - Uses providerRegistry.ts for dynamic provider loading
 * - Card provider config stored in financial_partners table
 * - ProviderFactory resolves providers via registry pattern
 */

/**
 * INITIALIZATION
 * 
 * Card provider is automatically initialized by providerRegistry.ts
 * during app startup. No manual registration needed.
 * 
 * Flow:
 * 1. App starts → initializeProviderRegistry() called
 * 2. Queries financial_partners table for all ACTIVE providers
 * 3. For provider_type='CARD', dynamically imports CardProvider
 * 4. Instantiates with config from database record
 * 5. Registers in ProviderFactory
 * 
 * See: /backend/payments/providerRegistry.ts
 */

/**
 * USAGE IN EXPRESS APP
 * 
 * import express from 'express';
 * import { initializeProviderRegistry } from './payments/providerRegistry.js';
 * import gatewayRoutes from './payments/gatewayRoutes.js';
 * 
 * const app = express();
 * 
 * async function startServer() {
 *   try {
 *     // Initialize all providers from database (includes CARD)
 *     await initializeProviderRegistry();
 *     
 *     // Mount gateway routes
 *     app.use('/v1/gateway', gatewayRoutes);
 *     
 *     // All payment requests route through:
 *     // POST /v1/gateway/payment/initiate { providerId: 'CARD', ... }
 *     
 *     const PORT = process.env.PORT || 3000;
 *     app.listen(PORT, () => {
 *       console.info(`✅ Payment system with CARD provider ready`);
 *     });
 *   } catch (error) {
 *     console.error('Failed to initialize payment providers:', error);
 *     process.exit(1);
 *   }
 * }
 * 
 * startServer();
 */

/**
 * CONFIGURATION IN DATABASE
 * 
 * Create a record in financial_partners table:
 * 
 * INSERT INTO financial_partners (
 *   name,
 *   provider_type,
 *   status,
 *   client_id,
 *   client_secret,
 *   api_key,
 *   merchant_id,
 *   supported_currencies,
 *   provider_fee,
 *   fixed_fee,
 *   settlement_fee,
 *   provider_metadata
 * ) VALUES (
 *   'Card Processor',
 *   'CARD',
 *   'ACTIVE',
 *   'card_processor_client_id',
 *   'encrypted_client_secret',
 *   'encrypted_api_key',
 *   'card_merchant_id',
 *   ARRAY['USD', 'EUR', 'GBP', 'TZS', 'KES', 'UGX'],
 *   0.025,      -- 2.5% provider fee
 *   0.3,        -- $0.30 fixed fee
 *   0.01,       -- 1% settlement fee
 *   '{"environment": "production", "webhookUrl": "https://api.orbi.com/webhooks/card"}'
 * );
 */

export {};
