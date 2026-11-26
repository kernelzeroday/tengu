import type { NotificationChannel, Severity, TenguStore } from "@tengu/store";

const SEVERITY_RANK: Record<Severity, number> = {
	info: 0,
	low: 1,
	medium: 2,
	high: 3,
	critical: 4,
};

export interface NotificationEvent {
	type: "finding_created" | "task_completed" | "approval_required" | "task_failed";
	severity: Severity;
	title: string;
	body: string;
	taskId?: number;
	metadata?: Record<string, unknown>;
}

export function maskSecrets(text: string): string {
	text = text.replace(/\b(access_token|refresh_token|api_key|apikey|token|secret|password)\s*([=:])\s*(["']?)([A-Za-z0-9._\-]{8,})\3/gi, "$1$2$3***REDACTED***$3");
	return text
		.replace(/\b(sk-[a-zA-Z0-9]{10,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,})\b/g, "***REDACTED***")
		.replace(/(authorization\s*:\s*bearer\s+)[^\s"']+/gi, "$1***REDACTED***");
}

export class NotificationDispatcher {
	private readonly store: TenguStore;

	constructor(store: TenguStore) {
		this.store = store;
	}

	previewPayload(event: NotificationEvent): { type: string; severity: Severity; title: string; body: string; taskId?: number } {
		return {
			type: event.type,
			severity: event.severity,
			title: maskSecrets(event.title),
			body: maskSecrets(event.body),
			taskId: event.taskId,
		};
	}

	async dispatch(event: NotificationEvent): Promise<Array<{ channel: string; ok: boolean; error?: string }>> {
		const channels = this.store.listNotificationChannels().filter((c) => c.enabled);
		const results: Array<{ channel: string; ok: boolean; error?: string }> = [];
		const maskedTitle = maskSecrets(event.title);
		const maskedBody = maskSecrets(event.body);

		for (const ch of channels) {
			if (ch.events.length > 0 && !ch.events.includes(event.type)) continue;
			if (SEVERITY_RANK[event.severity] < SEVERITY_RANK[ch.minSeverity]) continue;
			try {
				await this.sendToChannel(ch, maskedTitle, maskedBody, event);
				results.push({ channel: ch.name, ok: true });
			} catch (err) {
				results.push({ channel: ch.name, ok: false, error: err instanceof Error ? err.message : String(err) });
			}
		}
		return results;
	}

	private async sendToChannel(
		ch: NotificationChannel,
		title: string,
		body: string,
		event: NotificationEvent,
	): Promise<void> {
		const url = String(ch.config.url ?? ch.config.webhookUrl ?? "");
		if (ch.kind === "telegram") {
			const token = String(ch.config.botToken ?? "");
			const chatId = String(ch.config.chatId ?? "");
			const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ chat_id: chatId, text: `[${event.severity.toUpperCase()}] ${title}\n\n${body}` }),
				signal: AbortSignal.timeout(10_000),
			});
			if (!res.ok) throw new Error(`Telegram HTTP ${res.status}`);
			return;
		}
		if (ch.kind === "email") {
			const relayUrl = String(ch.config.relayUrl ?? ch.config.url ?? "");
			const to = String(ch.config.to ?? "");
			if (!relayUrl || !to) throw new Error(`Email channel ${ch.name} requires relayUrl and to`);
			const res = await fetch(relayUrl, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ to, subject: `[${event.severity.toUpperCase()}] ${title}`, text: body }),
				signal: AbortSignal.timeout(10_000),
			});
			if (!res.ok) throw new Error(`Email relay HTTP ${res.status}`);
			return;
		}
		if (!url) throw new Error(`Channel ${ch.name} missing webhook URL`);
		const payload =
			ch.kind === "dingtalk" || ch.kind === "wecom"
				? { msgtype: "markdown", markdown: { title, text: `### ${title}\n\n${body}`, content: `### ${title}\n\n${body}` } }
				: ch.kind === "feishu"
					? { msg_type: "text", content: { text: `[${event.severity.toUpperCase()}] ${title}\n${body}` } }
					: { event: event.type, severity: event.severity, title, body, taskId: event.taskId };

		const res = await fetch(url, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(payload),
			signal: AbortSignal.timeout(10_000),
		});
		if (!res.ok) throw new Error(`Webhook HTTP ${res.status}`);
	}
}
