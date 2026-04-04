
import { Category } from '../types.js';
import { Storage, STORAGE_KEYS } from '../backend/storage.js';
import { getSupabase, createAuthenticatedClient } from '../services/supabaseClient.js';
import { DataVault } from '../backend/security/encryption.js';
import { DataProtection } from '../backend/security/DataProtection.js';

export class CategoryService {
    private getDb(token?: string) {
        if (token) {
            const client = createAuthenticatedClient(token);
            if (client) return client;
        }
        return getSupabase();
    }

    async getFromDBLocal(): Promise<Category[]> {
        const raw = Storage.getFromDB(STORAGE_KEYS.CATEGORIES) as any[];
        return this.hydrateCategories(raw);
    }

    async fetchForUser(userId: string, token?: string): Promise<Category[]> {
        const sb = this.getDb(token);
        if (!sb) return this.getFromDBLocal();

        const { data, error } = await sb.from('categories').select('*').eq('user_id', userId);
        if (error || !data) return [];

        return this.hydrateCategories(data);
    }

    private async hydrateCategories(raw: any[]): Promise<Category[]> {
        return await Promise.all(raw.map(async c => ({
            ...c,
            budget: typeof c.budget === 'string' ? await DataProtection.decryptAmount(c.budget) : c.budget
        })));
    }

    private toDbPayload(category: Record<string, any>, encryptedBudget: string) {
        const payload: Record<string, any> = {
            id: category.id,
            user_id: category.user_id ?? category.userId,
            organization_id: category.organization_id ?? category.organizationId,
            name: category.name,
            budget: encryptedBudget,
            color: category.color,
            icon: category.icon,
            currency: category.currency,
            period: category.period,
            hard_limit: category.hard_limit ?? category.hardLimit,
            is_corporate: category.is_corporate ?? category.isCorporate,
            budget_interval: category.budget_interval ?? category.budgetInterval,
            budget_period: category.budget_period ?? category.budgetPeriod,
        };

        Object.keys(payload).forEach((key) => payload[key] === undefined && delete payload[key]);
        return payload;
    }

    async postCategory(c: Category, token?: string) { 
        const encryptedBudget = await DataProtection.encryptAmount(Number(c.budget || 0));
        const sb = this.getDb(token);
        if (sb) {
            const payload = this.toDbPayload(c as Record<string, any>, encryptedBudget);
            const { data, error } = await sb
                .from('categories')
                .upsert(payload)
                .select()
                .single();
            if (error) {
                console.error('[CategoryService] Upsert error:', error);
                throw new Error(error.message);
            }
            if (data) {
                const hydrated = await this.hydrateCategories([data]);
                return { data: hydrated[0], error: null };
            }
        }

        let items = Storage.getFromDB<any>(STORAGE_KEYS.CATEGORIES); 
        const index = items.findIndex((item: any) => String(item.id) === String(c.id));
        if (index === -1) {
            items.push({ ...c, budget: encryptedBudget });
        } else {
            items[index] = { ...items[index], ...c, budget: encryptedBudget };
        }
        Storage.saveToDB(STORAGE_KEYS.CATEGORIES, items); 
        return { data: c, error: null }; 
    }

    // Fixed: Added missing updateCategory method
    async updateCategory(c: Category, token?: string) { 
        const encryptedBudget = await DataProtection.encryptAmount(Number(c.budget || 0));
        const sb = this.getDb(token);
        if (sb) {
            const payload = this.toDbPayload(c as Record<string, any>, encryptedBudget);
            delete payload.id;
            delete payload.user_id;
            const { error } = await sb
                .from('categories')
                .update(payload)
                .eq('id', c.id);
            if (error) {
                console.error('[CategoryService] Update error:', error);
                throw new Error(error.message);
            }
        }
        let items = Storage.getFromDB<any>(STORAGE_KEYS.CATEGORIES);
        const index = items.findIndex((item: any) => String(item.id) === String(c.id));
        if (index !== -1) {
            items[index] = { ...items[index], ...c, budget: encryptedBudget };
            Storage.saveToDB(STORAGE_KEYS.CATEGORIES, items);
        }
        return { error: null }; 
    }

    async deleteCategory(id: string, token?: string) { 
        const sb = this.getDb(token);
        if (sb) {
            const { error } = await sb.from('categories').delete().eq('id', id);
            if (error) {
                console.error('[CategoryService] Delete error:', error);
                throw new Error(error.message);
            }
        }
        let items = Storage.getFromDB<any>(STORAGE_KEYS.CATEGORIES);
        items = items.filter((item: any) => String(item.id) !== String(id));
        Storage.saveToDB(STORAGE_KEYS.CATEGORIES, items);
        return { error: null }; 
    }
}
