import { checkTargetScope, type ApprovalRequest, type InterceptRule, type TenguStore } from "@tengu/store";
import { BUILTIN_INTERCEPT_RULES } from "./builtin-rules.ts";
import { analyzeToolInputStatic, type StaticRiskSignal } from "./static-analyzer.ts";

export interface InterceptContext {
	taskId: number;
	intentId?: number | null;
	toolName: string;
	toolArgs: unknown;
	targetUrlOrHost?: string;
}

export interface InterceptDecision {
	allowed: boolean;
	action: "allow" | "deny" | "ask" | "judge";
	reason: string;
	ruleName?: string;
	approvalId?: number;
	staticSignals: StaticRiskSignal[];
}

export type JudgeCallback = (input: {
	rule: InterceptRule;
	toolName: string;
	serializedArgs: string;
	staticSignals: StaticRiskSignal[];
	signal: AbortSignal;
}) => Promise<{ allow: boolean; reason: string; rawOutput?: string }>;

export type AskCallback = (req: ApprovalRequest) => Promise<{ approved: boolean; decidedBy: string; reason?: string }>;

export interface InterceptEngineOptions {
	store: TenguStore;
	judge?: JudgeCallback;
	ask?: AskCallback;
	/** Default decision for `ask` rules when running non-interactively without an AskCallback. */
	nonInteractiveAskDefault?: "deny" | "allow";
}

function ruleMatches(rule: InterceptRule, toolName: string, serializedArgs: string, targetHost?: string): boolean {
	if (!rule.enabled) return false;
	if (rule.scope === "asset" && rule.assetPattern) {
		if (!targetHost) return false;
		try {
			if (!new RegExp(rule.assetPattern, "i").test(targetHost)) return false;
		} catch {
			if (!targetHost.toLowerCase().includes(rule.assetPattern.toLowerCase())) return false;
		}
	}
	const haystack = rule.target === "tool_name" ? toolName : serializedArgs;
	if (rule.matchType === "string") {
		return haystack === rule.pattern || haystack.includes(rule.pattern);
	}
	try {
		return new RegExp(rule.pattern, "i").test(haystack);
	} catch {
		return false;
	}
}

export class InterceptEngine {
	private readonly store: TenguStore;
	private readonly judge?: JudgeCallback;
	private readonly ask?: AskCallback;
	private readonly nonInteractiveAskDefault: "deny" | "allow";

	constructor(options: InterceptEngineOptions) {
		this.store = options.store;
		this.judge = options.judge;
		this.ask = options.ask;
		this.nonInteractiveAskDefault = options.nonInteractiveAskDefault ?? "deny";
	}

	/** Idempotently seeds all built-in three-layer intercept rules. */
	seedBuiltinRules(): InterceptRule[] {
		const existing = new Set(this.store.listInterceptRules().map((r) => r.name));
		const seeded: InterceptRule[] = [];
		for (const rule of BUILTIN_INTERCEPT_RULES) {
			if (!existing.has(rule.name)) {
				seeded.push(this.store.upsertInterceptRule(rule));
			}
		}
		return seeded;
	}

	async evaluate(ctx: InterceptContext): Promise<InterceptDecision> {
		const serializedArgs = typeof ctx.toolArgs === "string" ? ctx.toolArgs : JSON.stringify(ctx.toolArgs ?? {});
		const staticSignals = analyzeToolInputStatic(ctx.toolName, serializedArgs);

		// 1. Scope boundary guard
		if (ctx.targetUrlOrHost) {
			const task = this.store.getTask(ctx.taskId);
			const scopeRules = [
				...this.store.listTaskScope(ctx.taskId),
				...(task?.companyId ? this.store.listCompanyScope(task.companyId) : []),
			];
			if (scopeRules.length > 0) {
				const scopeCheck = checkTargetScope(ctx.targetUrlOrHost, scopeRules);
				if (!scopeCheck.inScope) {
					const reason = scopeCheck.excludedBy
						? `Target ${ctx.targetUrlOrHost} is explicitly excluded by scope rule: ${scopeCheck.excludedBy}`
						: `Target ${ctx.targetUrlOrHost} is outside authorized task/company scope.`;
					const approval = this.store.createApprovalRequest({
						taskId: ctx.taskId,
						intentId: ctx.intentId ?? null,
						ruleId: null,
						ruleName: "scope_guard",
						toolName: ctx.toolName,
						toolInput: serializedArgs,
						action: "deny",
						status: "denied",
						reason,
						judgeOutput: "",
						decidedBy: "scope_guard",
					});
					return { allowed: false, action: "deny", reason, ruleName: "scope_guard", approvalId: approval.id, staticSignals };
				}
			}
		}

		// 2. Evaluate enabled rules (priority descending)
		const rawRules = this.store.listInterceptRules({ taskId: ctx.taskId, enabledOnly: true });
		const classRank = (r: InterceptRule) => (r.action === "deny" || r.ruleClass === "hard_deny" ? 0 : r.action === "judge" ? 1 : r.action === "ask" ? 2 : 3);
		const rules = [...rawRules].sort((a, b) => classRank(a) - classRank(b) || b.priority - a.priority);
		for (const rule of rules) {
			if (!ruleMatches(rule, ctx.toolName, serializedArgs, ctx.targetUrlOrHost)) continue;

			if (rule.action === "allow") {
				return { allowed: true, action: "allow", reason: rule.message || "Allowed by rule", ruleName: rule.name, staticSignals };
			}

			if (rule.action === "deny") {
				const reason = rule.message || `Denied by intercept rule ${rule.name}`;
				const approval = this.store.createApprovalRequest({
					taskId: ctx.taskId,
					intentId: ctx.intentId ?? null,
					ruleId: rule.id,
					ruleName: rule.name,
					toolName: ctx.toolName,
					toolInput: serializedArgs,
					action: "deny",
					status: "denied",
					reason,
					judgeOutput: "",
					decidedBy: "hard_deny",
				});
				return { allowed: false, action: "deny", reason, ruleName: rule.name, approvalId: approval.id, staticSignals };
			}

			if (rule.action === "judge") {
				const approval = this.store.createApprovalRequest({
					taskId: ctx.taskId,
					intentId: ctx.intentId ?? null,
					ruleId: rule.id,
					ruleName: rule.name,
					toolName: ctx.toolName,
					toolInput: serializedArgs,
					action: "judge",
					status: "pending",
					reason: rule.message,
					judgeOutput: "",
					decidedBy: "",
				});

				if (!this.judge) {
					const fallbackAllow = rule.timeoutAction === "allow";
					this.store.resolveApprovalRequest(
						approval.id,
						fallbackAllow ? "approved" : "denied",
						"judge_unavailable",
						`No LLM judge configured; applied fallback action: ${rule.timeoutAction}`,
					);
					return {
						allowed: fallbackAllow,
						action: "judge",
						reason: `No LLM judge configured; fallback=${rule.timeoutAction}`,
						ruleName: rule.name,
						approvalId: approval.id,
						staticSignals,
					};
				}

				const timeoutMs = (rule.timeoutEnabled && rule.timeoutSeconds > 0 ? rule.timeoutSeconds : 20) * 1000;
				const controller = new AbortController();
				const timer = setTimeout(() => controller.abort(), timeoutMs);
				try {
					const verdict = await this.judge({
						rule,
						toolName: ctx.toolName,
						serializedArgs,
						staticSignals,
						signal: controller.signal,
					});
					this.store.resolveApprovalRequest(
						approval.id,
						verdict.allow ? "approved" : "denied",
						"llm_judge",
						verdict.reason,
						verdict.rawOutput ?? "",
					);
					return {
						allowed: verdict.allow,
						action: "judge",
						reason: verdict.reason,
						ruleName: rule.name,
						approvalId: approval.id,
						staticSignals,
					};
				} catch (err) {
					const fallbackAllow = rule.timeoutAction === "allow";
					const errMsg = err instanceof Error ? err.message : String(err);
					this.store.resolveApprovalRequest(
						approval.id,
						"timed_out",
						"judge_timeout",
						`Judge failed/timed out (${errMsg}); applied fallback=${rule.timeoutAction}`,
					);
					return {
						allowed: fallbackAllow,
						action: "judge",
						reason: `Judge failed/timed out (${errMsg}); fallback=${rule.timeoutAction}`,
						ruleName: rule.name,
						approvalId: approval.id,
						staticSignals,
					};
				} finally {
					clearTimeout(timer);
				}
			}

			if (rule.action === "ask") {
				const approval = this.store.createApprovalRequest({
					taskId: ctx.taskId,
					intentId: ctx.intentId ?? null,
					ruleId: rule.id,
					ruleName: rule.name,
					toolName: ctx.toolName,
					toolInput: serializedArgs,
					action: "ask",
					status: "pending",
					reason: rule.message,
					judgeOutput: "",
					decidedBy: "",
				});

				if (!this.ask) {
					const allow = this.nonInteractiveAskDefault === "allow";
					this.store.resolveApprovalRequest(
						approval.id,
						allow ? "approved" : "denied",
						"non_interactive_default",
						`Non-interactive mode default: ${this.nonInteractiveAskDefault}`,
					);
					return {
						allowed: allow,
						action: "ask",
						reason: `Operator confirmation required (${rule.name}); non-interactive default=${this.nonInteractiveAskDefault}`,
						ruleName: rule.name,
						approvalId: approval.id,
						staticSignals,
					};
				}

				try {
					const decision = await this.ask(approval);
					const approved = Boolean(decision?.approved);
					this.store.resolveApprovalRequest(
						approval.id,
						approved ? "approved" : "denied",
						decision?.decidedBy ?? "operator",
						decision?.reason ?? "",
					);
					return {
						allowed: approved,
						action: "ask",
						reason: decision?.reason || (approved ? "Approved by operator" : "Denied by operator"),
						ruleName: rule.name,
						approvalId: approval.id,
						staticSignals,
					};
				} catch (err) {
					const msg = err instanceof Error ? err.message : String(err);
					this.store.resolveApprovalRequest(approval.id, "denied", "ask_error_fallback", msg);
					return {
						allowed: false,
						action: "ask",
						reason: `Approval handler error (fail-closed): ${msg}`,
						ruleName: rule.name,
						approvalId: approval.id,
						staticSignals,
					};
				}
			}
		}

		// 3. Critical static risk signal fallback if no explicit rule matched
		const highSignal = staticSignals.find((s) => s.severity === "critical" || s.severity === "high");
		if (highSignal) {
			const approval = this.store.createApprovalRequest({
				taskId: ctx.taskId,
				intentId: ctx.intentId ?? null,
				ruleId: null,
				ruleName: `static_${highSignal.code}`,
				toolName: ctx.toolName,
				toolInput: serializedArgs,
				action: "deny",
				status: "denied",
				reason: highSignal.detail,
				judgeOutput: "",
				decidedBy: "static_analyzer",
			});
			return {
				allowed: false,
				action: "deny",
				reason: `Blocked by static analyzer (${highSignal.code}): ${highSignal.detail}`,
				ruleName: `static_${highSignal.code}`,
				approvalId: approval.id,
				staticSignals,
			};
		}

		return { allowed: true, action: "allow", reason: "No intercept rule triggered", staticSignals };
	}
}
