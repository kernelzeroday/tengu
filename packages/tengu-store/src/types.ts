export type TaskStatus =
	| "draft"
	| "queued"
	| "running"
	| "paused"
	| "completed"
	| "failed"
	| "stopped"
	| "archived";

export type AssetKind =
	| "domain"
	| "subdomain"
	| "ip"
	| "cidr"
	| "port"
	| "service"
	| "site"
	| "endpoint"
	| "parameter"
	| "repo"
	| "cloud"
	| "credential"
	| "other";

export type ExplorationNodeKind = "begin" | "intent" | "fact" | "finding" | "goal" | "hint";

export type IntentState = "open" | "running" | "exhausted" | "blocked" | "stopped" | "retired" | "done";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus = "open" | "verified" | "false_positive" | "fixed" | "accepted";

export type InterceptAction = "deny" | "ask" | "judge" | "allow";
export type InterceptClass = "hard_deny" | "judge" | "ask";
export type InterceptTarget = "tool_name" | "tool_input";
export type InterceptMatchType = "string" | "regex";
export type InterceptScope = "global" | "task" | "asset";
export type ApprovalStatus = "pending" | "approved" | "denied" | "timed_out";

export interface Company {
	id: number;
	name: string;
	description: string;
	createdAt: string;
	updatedAt: string;
}

export interface CompanyScopeRule {
	id: number;
	companyId: number;
	pattern: string;
	kind: "domain" | "cidr" | "ip" | "url" | "regex";
	exclude: boolean;
	note: string;
	createdAt: string;
}

export interface Task {
	id: number;
	name: string;
	description: string;
	companyId: number | null;
	parentTaskId: number | null;
	category: string;
	status: TaskStatus;
	autopilot: boolean;
	coverageEnabled: boolean;
	scopeWriteGuard: boolean;
	scopeInheritWrites: boolean;
	maxWorkers: number;
	maxTurns: number;
	createdAt: string;
	updatedAt: string;
	completedAt: string | null;
}

export interface TaskScopeRule {
	id: number;
	taskId: number;
	pattern: string;
	kind: "domain" | "cidr" | "ip" | "url" | "regex";
	exclude: boolean;
	note: string;
	createdAt: string;
}

export interface TaskConstraint {
	id: number;
	taskId: number;
	text: string;
	enforced: boolean;
	createdAt: string;
}

export interface TaskAuthProfile {
	id: number;
	taskId: number;
	name: string;
	role: string;
	authType: "cookie" | "bearer" | "basic" | "header" | "custom";
	headers: Record<string, string>;
	cookies: Record<string, string>;
	loginUrl: string;
	metadata: Record<string, unknown>;
	updatedAt: string;
}

export interface AssetNode {
	id: number;
	companyId: number | null;
	taskId: number | null;
	kind: AssetKind;
	value: string;
	normalizedKey: string;
	label: string;
	metadata: Record<string, unknown>;
	tested: boolean;
	testedByIntentId: number | null;
	source: string;
	createdAt: string;
	updatedAt: string;
}

export interface AssetEdge {
	id: number;
	fromAssetId: number;
	toAssetId: number;
	relation: string;
	metadata: Record<string, unknown>;
	createdAt: string;
}

export interface AssetCoverageSummary {
	total: number;
	tested: number;
	untested: number;
	byKind: Record<string, { total: number; tested: number }>;
}

export interface ExplorationNode {
	id: number;
	taskId: number;
	kind: ExplorationNodeKind;
	state: string;
	summary: string;
	payload: Record<string, unknown>;
	assetIds: number[];
	blockedReason: string;
	inherited: boolean;
	sourceTaskId: number | null;
	workerId: string;
	createdAt: string;
	updatedAt: string;
}

export interface ExplorationEdge {
	id: number;
	taskId: number;
	fromNodeId: number;
	toNodeId: number;
	relation: "derives" | "yields" | "proves" | "blocks" | "requires" | "anchors";
	createdAt: string;
}

export interface Finding {
	id: number;
	taskId: number;
	nodeId: number | null;
	intentId: number | null;
	title: string;
	vulnClass: string;
	severity: Severity;
	status: FindingStatus;
	summary: string;
	description: string;
	reproduction: string;
	remediation: string;
	evidence: string;
	evidenceIds: number[];
	assetIds: number[];
	cvss: number | null;
	cwe: string;
	fingerprint: string;
	createdAt: string;
	updatedAt: string;
}

export interface FindingRetest {
	id: number;
	findingId: number;
	taskId: number;
	status: "still_vulnerable" | "fixed" | "inconclusive";
	notes: string;
	evidence: string;
	createdAt: string;
}

export interface ArtifactRecord {
	id: number;
	taskId: number;
	intentId: number | null;
	name: string;
	kind: string;
	mimeType: string;
	sha256: string;
	sizeBytes: number;
	path: string;
	description: string;
	createdAt: string;
}

export interface InterceptRule {
	id: number;
	name: string;
	scope: InterceptScope;
	taskId: number | null;
	assetPattern: string;
	target: InterceptTarget;
	matchType: InterceptMatchType;
	pattern: string;
	action: InterceptAction;
	ruleClass: InterceptClass;
	rationale: string;
	message: string;
	priority: number;
	enabled: boolean;
	seedBatch: string;
	timeoutEnabled: boolean;
	timeoutSeconds: number;
	timeoutAction: "deny" | "ask" | "allow";
	createdAt: string;
	updatedAt: string;
}

export interface ApprovalRequest {
	id: number;
	taskId: number;
	intentId: number | null;
	ruleId: number | null;
	ruleName: string;
	toolName: string;
	toolInput: string;
	action: InterceptAction;
	status: ApprovalStatus;
	reason: string;
	judgeOutput: string;
	decidedBy: string;
	createdAt: string;
	decidedAt: string | null;
}

export interface TrafficRecord {
	id: number;
	taskId: number;
	intentId: number | null;
	findingId: number | null;
	method: string;
	url: string;
	host: string;
	statusCode: number;
	requestHeaders: Record<string, string>;
	requestBody: string;
	responseHeaders: Record<string, string>;
	responseBody: string;
	durationMs: number;
	createdAt: string;
}

export interface WorkerTraceEntry {
	id: number;
	taskId: number;
	intentId: number;
	workerId: string;
	turn: number;
	toolName: string;
	toolArgs: string;
	toolOutput: string;
	isError: boolean;
	durationMs: number;
	createdAt: string;
}

export interface LlmUsageRecord {
	id: number;
	taskId: number;
	intentId: number | null;
	role: string;
	provider: string;
	model: string;
	inputTokens: number;
	outputTokens: number;
	cacheReadTokens: number;
	costUsd: number;
	createdAt: string;
}

export interface SideQuestion {
	id: number;
	taskId: number;
	question: string;
	answer: string;
	status: "open" | "answered";
	createdAt: string;
	answeredAt: string | null;
}

export interface NotificationChannel {
	id: number;
	name: string;
	kind: "webhook" | "telegram" | "dingtalk" | "feishu" | "wecom" | "email";
	enabled: boolean;
	config: Record<string, unknown>;
	events: string[];
	minSeverity: Severity;
	createdAt: string;
}

export interface VulnIntelEntry {
	id: string;
	source: "nvd" | "ghsa" | "kev" | "nuclei" | "poc" | "custom";
	cveId: string;
	title: string;
	severity: Severity;
	cvss: number | null;
	affectedProduct: string;
	affectedVersions: string;
	description: string;
	references: string[];
	pocTemplate: string;
	publishedAt: string;
	updatedAt: string;
}

export interface GraphOverview {
	taskId: number;
	goals: ExplorationNode[];
	constraints: TaskConstraint[];
	intents: Array<{
		id: number;
		summary: string;
		state: string;
		blockedReason?: string;
		assetIds: number[];
		parents: number[];
		yields: number[];
		tokens: number;
		wallMs?: number;
	}>;
	recentFacts: ExplorationNode[];
	findings: Finding[];
	hints: ExplorationNode[];
	coverage: AssetCoverageSummary | null;
}

export interface TenguStore {
	close(): void;

	// Companies & Scope
	createCompany(name: string, description?: string): Company;
	listCompanies(): Company[];
	getCompany(id: number): Company | null;
	addCompanyScope(rule: Omit<CompanyScopeRule, "id" | "createdAt">): CompanyScopeRule;
	listCompanyScope(companyId: number): CompanyScopeRule[];

	// Tasks
	createTask(input: {
		name: string;
		description?: string;
		companyId?: number | null;
		parentTaskId?: number | null;
		category?: string;
		autopilot?: boolean;
		coverageEnabled?: boolean;
		scopeWriteGuard?: boolean;
		scopeInheritWrites?: boolean;
		maxWorkers?: number;
		maxTurns?: number;
	}): Task;
	getTask(id: number): Task | null;
	listTasks(status?: TaskStatus): Task[];
	updateTaskStatus(id: number, status: TaskStatus): Task | null;
	updateTaskConfig(
		id: number,
		patch: Partial<Pick<Task, "name" | "description" | "autopilot" | "coverageEnabled" | "scopeWriteGuard" | "scopeInheritWrites" | "maxWorkers" | "maxTurns">>,
	): Task | null;
	addTaskScope(rule: Omit<TaskScopeRule, "id" | "createdAt">): TaskScopeRule;
	listTaskScope(taskId: number): TaskScopeRule[];
	setTaskConstraints(taskId: number, constraints: string[]): TaskConstraint[];
	listTaskConstraints(taskId: number): TaskConstraint[];

	// Auth Profiles
	upsertAuthProfile(profile: Omit<TaskAuthProfile, "id" | "updatedAt">): TaskAuthProfile;
	getAuthProfile(taskId: number, name: string): TaskAuthProfile | null;
	listAuthProfiles(taskId: number): TaskAuthProfile[];

	// Asset Graph
	upsertAssets(
		assets: Array<{
			companyId?: number | null;
			taskId?: number | null;
			kind: AssetKind;
			value: string;
			label?: string;
			metadata?: Record<string, unknown>;
			source?: string;
		}>,
	): AssetNode[];
	getAsset(id: number): AssetNode | null;
	listAssets(filter?: {
		taskId?: number;
		companyId?: number;
		kind?: AssetKind;
		tested?: boolean;
		query?: string;
		limit?: number;
	}): AssetNode[];
	markAssetsTested(assetIds: number[], intentId?: number | null): void;
	addAssetEdge(fromAssetId: number, toAssetId: number, relation: string, metadata?: Record<string, unknown>): AssetEdge;
	getAssetNeighbors(assetId: number): { incoming: Array<{ edge: AssetEdge; asset: AssetNode }>; outgoing: Array<{ edge: AssetEdge; asset: AssetNode }> };
	getAssetCoverage(taskId: number): AssetCoverageSummary;

	// Exploration Graph
	addExplorationNode(input: {
		taskId: number;
		kind: ExplorationNodeKind;
		state?: string;
		summary: string;
		payload?: Record<string, unknown>;
		assetIds?: number[];
		blockedReason?: string;
		inherited?: boolean;
		sourceTaskId?: number | null;
		workerId?: string;
	}): ExplorationNode;
	getExplorationNode(id: number): ExplorationNode | null;
	updateExplorationNode(
		id: number,
		patch: Partial<Pick<ExplorationNode, "state" | "summary" | "payload" | "blockedReason" | "workerId">>,
	): ExplorationNode | null;
	listExplorationNodes(filter: {
		taskId: number;
		kind?: ExplorationNodeKind;
		state?: string;
		q?: string;
		before?: number;
		limit?: number;
	}): { nodes: ExplorationNode[]; total: number; hasMore: boolean; nextBefore: number | null };
	addExplorationEdge(
		taskId: number,
		fromNodeId: number,
		toNodeId: number,
		relation: ExplorationEdge["relation"],
	): ExplorationEdge;
	listExplorationEdges(taskId: number): ExplorationEdge[];
	getGraphOverview(taskId: number): GraphOverview;

	// Findings & Retests
	addFinding(input: Omit<Finding, "id" | "createdAt" | "updatedAt">): Finding;
	getFinding(id: number): Finding | null;
	listFindings(taskId?: number): Finding[];
	updateFindingStatus(id: number, status: FindingStatus): Finding | null;
	findByFingerprint(fingerprint: string): Finding | null;
	addFindingRetest(retest: Omit<FindingRetest, "id" | "createdAt">): FindingRetest;
	listFindingRetests(findingId: number): FindingRetest[];

	// Artifacts & Evidence
	addArtifact(artifact: Omit<ArtifactRecord, "id" | "createdAt">): ArtifactRecord;
	listArtifacts(taskId: number): ArtifactRecord[];
	getArtifact(id: number): ArtifactRecord | null;

	// Intercept Rules & Approvals
	upsertInterceptRule(rule: Omit<InterceptRule, "id" | "createdAt" | "updatedAt">): InterceptRule;
	listInterceptRules(filter?: { scope?: InterceptScope; taskId?: number; enabledOnly?: boolean }): InterceptRule[];
	createApprovalRequest(req: Omit<ApprovalRequest, "id" | "createdAt" | "decidedAt">): ApprovalRequest;
	getApprovalRequest(id: number): ApprovalRequest | null;
	listApprovalRequests(filter?: { taskId?: number; status?: ApprovalStatus }): ApprovalRequest[];
	resolveApprovalRequest(
		id: number,
		status: ApprovalStatus,
		decidedBy: string,
		reason?: string,
		judgeOutput?: string,
	): ApprovalRequest | null;

	// Traffic
	addTrafficRecord(rec: Omit<TrafficRecord, "id" | "createdAt">): TrafficRecord;
	listTrafficRecords(filter?: { taskId?: number; intentId?: number; findingId?: number; limit?: number }): TrafficRecord[];

	// Worker Traces
	addWorkerTrace(entry: Omit<WorkerTraceEntry, "id" | "createdAt">): WorkerTraceEntry;
	listWorkerTraces(filter: { taskId: number; intentId?: number; limit?: number }): WorkerTraceEntry[];
	searchWorkerTraces(taskId: number, query: string, limit?: number): WorkerTraceEntry[];

	// LLM Usage
	recordLlmUsage(usage: Omit<LlmUsageRecord, "id" | "createdAt">): LlmUsageRecord;
	getTaskTokenTotals(taskId: number): { totalTokens: number; costUsd: number; byIntent: Record<number, number> };
	getTaskUsageBreakdown(taskId: number): {
		totalInputTokens: number;
		totalOutputTokens: number;
		totalTokens: number;
		knownCostUsd: number | null;
		byModel: Array<{ provider: string; model: string; inputTokens: number; outputTokens: number; totalTokens: number; costUsd: number | null }>;
	};

	// Side Questions
	addSideQuestion(taskId: number, question: string): SideQuestion;
	answerSideQuestion(id: number, answer: string): SideQuestion | null;
	listSideQuestions(taskId: number): SideQuestion[];

	// Notification Channels
	upsertNotificationChannel(ch: Omit<NotificationChannel, "id" | "createdAt">): NotificationChannel;
	listNotificationChannels(): NotificationChannel[];

	// Vuln Intel Cache
	upsertVulnIntel(entries: VulnIntelEntry[]): number;
	searchVulnIntel(query: string, limit?: number): VulnIntelEntry[];
	getVulnIntel(idOrCve: string): VulnIntelEntry | null;
	listRecentCriticalVulns(limit?: number): VulnIntelEntry[];

	// Settings
	getSetting(key: string): string | null;
	setSetting(key: string, value: string): void;
}
