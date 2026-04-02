export const quotePostgrestFilterValue = (value: unknown): string => {
    const normalized = String(value ?? '');
    return `"${normalized.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
};

export const buildPostgrestEqualsFilter = (column: string, value: unknown): string =>
    `${column}.eq.${quotePostgrestFilterValue(value)}`;

export const buildPostgrestLikeFilter = (column: string, value: unknown): string =>
    `${column}.ilike.${quotePostgrestFilterValue(`%${String(value ?? '')}%`)}`;

export const buildPostgrestOrFilter = (
    filters: Array<{ column: string; operator: 'eq' | 'ilike'; value: unknown }>,
): string =>
    filters
        .map((filter) =>
            filter.operator === 'ilike'
                ? buildPostgrestLikeFilter(filter.column, filter.value)
                : buildPostgrestEqualsFilter(filter.column, filter.value),
        )
        .join(',');
