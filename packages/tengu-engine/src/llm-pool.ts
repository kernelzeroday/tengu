import type { Api, Model } from "@earendil-works/pi-ai";
import type { TenguStore } from "@tengu/store";

export interface PoolEndpoint {
	id: string;
	model: Model<Api>;
	apiKey?: string;
	weight: number;
	healthy: boolean;
	consecutiveFailures: number;
	cooldownUntil: number;
	lastError: string;
}

const REFUSAL_PATTERNS = [
	/\bi (?:cannot|can't|am unable to|won't) (?:assist|help|comply|provide|perform|execute)\b/i,
	/\bagainst my (?:safety|ethical) (?:guidelines|policies)\b/i,
	/\bunauthorized (?:hacking|penetration testing|cyberattack)\b/i,
];

export function detectRefusal(text: string): boolean {
	if (!text || text.length > 1500) return false;
	return REFUSAL_PATTERNS.some((re) => re.test(text));
}

/**
 * Manages a pool of LLM model endpoints with health tracking, exponential cooldown,
 * automatic failover, and usage accounting into TenguStore.
 */
export class LlmPool {
	private readonly endpoints: PoolEndpoint[] = [];
	private readonly store?: TenguStore;
	private cursor = 0;

	constructor(endpoints: Array<{ id: string; model: Model<Api>; apiKey?: string; weight?: number }>, store?: TenguStore) {
		this.store = store;
		for (const ep of endpoints) {
			this.endpoints.push({
				id: ep.id,
				model: ep.model,
				apiKey: ep.apiKey,
				weight: ep.weight ?? 1,
				healthy: true,
				consecutiveFailures: 0,
				cooldownUntil: 0,
				lastError: "",
			});
		}
	}

	addEndpoint(ep: { id: string; model: Model<Api>; apiKey?: string; weight?: number }): void {
		this.endpoints.push({
			id: ep.id,
			model: ep.model,
			apiKey: ep.apiKey,
			weight: ep.weight ?? 1,
			healthy: true,
			consecutiveFailures: 0,
			cooldownUntil: 0,
			lastError: "",
		});
	}

	listEndpoints(): PoolEndpoint[] {
		return this.endpoints.map((e) => ({ ...e }));
	}

	select(): PoolEndpoint | null {
		if (this.endpoints.length === 0) return null;
		const now = Date.now();
		for (let i = 0; i < this.endpoints.length; i++) {
			const idx = (this.cursor + i) % this.endpoints.length;
			const ep = this.endpoints[idx];
			if (ep.healthy || ep.cooldownUntil <= now) {
				this.cursor = (idx + 1) % this.endpoints.length;
				return ep;
			}
		}
		// All in cooldown: pick the one whose cooldown expires earliest
		return [...this.endpoints].sort((a, b) => a.cooldownUntil - b.cooldownUntil)[0] ?? null;
	}

	markSuccess(id: string): void {
		const ep = this.endpoints.find((e) => e.id === id);
		if (!ep) return;
		ep.healthy = true;
		ep.consecutiveFailures = 0;
		ep.cooldownUntil = 0;
		ep.lastError = "";
	}

	markFailure(id: string, error: string): void {
		const ep = this.endpoints.find((e) => e.id === id);
		if (!ep) return;
		ep.consecutiveFailures++;
		ep.healthy = false;
		ep.lastError = error;
		const backoffMs = Math.min(5_000 * 2 ** (ep.consecutiveFailures - 1), 120_000);
		ep.cooldownUntil = Date.now() + backoffMs;
	}

	recordUsage(input: {
		taskId: number;
		intentId?: number | null;
		role: string;
		model: Model<Api>;
		inputTokens: number;
		outputTokens: number;
		cacheReadTokens?: number;
		costUsd?: number;
	}): void {
		if (!this.store) return;
		this.store.recordLlmUsage({
			taskId: input.taskId,
			intentId: input.intentId ?? null,
			role: input.role,
			provider: input.model.provider,
			model: input.model.id,
			inputTokens: input.inputTokens,
			outputTokens: input.outputTokens,
			cacheReadTokens: input.cacheReadTokens ?? 0,
			costUsd: input.costUsd ?? 0,
		});
	}
}
