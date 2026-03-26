type PerfResult<T> = Promise<T>;

export class PerfMonitor {
    static async track<T>(
        label: string,
        work: () => PerfResult<T>,
        thresholdMs: number = Number(process.env.ORBI_PERF_WARN_MS || 250),
    ): PerfResult<T> {
        const start = Date.now();
        try {
            return await work();
        } finally {
            const elapsed = Date.now() - start;
            if (elapsed >= thresholdMs) {
                console.info(`[Perf] ${label} took ${elapsed}ms`);
            }
        }
    }
}

