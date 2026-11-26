export interface StaticRiskSignal {
	code: string;
	severity: "critical" | "high" | "medium";
	detail: string;
}

const SHELL_RISK_PATTERNS: Array<{ code: string; severity: StaticRiskSignal["severity"]; re: RegExp; detail: string }> = [
	{
		code: "base64_shell_exec",
		severity: "high",
		re: /base64\s+(?:-d|--decode)[^\n|]*\|\s*(?:ba|z|da|a)?sh\b/i,
		detail: "Base64-decoded payload piped directly into shell execution.",
	},
	{
		code: "sed_inplace_etc",
		severity: "high",
		re: /\bsed\s+[^\n]*-i[^\n]*\/etc\//i,
		detail: "In-place sed modification targeting /etc/.",
	},
	{
		code: "python_rmtree",
		severity: "high",
		re: /shutil\.rmtree\s*\(\s*['"]\/(?:['"]|etc|usr|var|home|root)/i,
		detail: "Python shutil.rmtree targeting a sensitive system directory.",
	},
	{
		code: "python_encoded_exec",
		severity: "medium",
		re: /\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|codecs\.decode|bytes\.fromhex)/i,
		detail: "Obfuscated dynamic Python code execution.",
	},
	{
		code: "dev_tcp_reverse_shell",
		severity: "critical",
		re: /\/dev\/(?:tcp|udp)\/[^\s"']+\/\d+/i,
		detail: "Bash /dev/tcp or /dev/udp reverse shell redirection.",
	},
	{
		code: "python_os_shell_exec",
		severity: "medium",
		re: /\b(?:os\.system|subprocess\.(?:Popen|run|call|check_output))\s*\(/i,
		detail: "Python OS/subprocess command execution.",
	},
	{
		code: "chmod_world_writable_sys",
		severity: "high",
		re: /\bchmod\s+(?:-R\s+)?0?777\s+\/(?:etc|usr|bin|sbin|var|root|\s|$)/i,
		detail: "Recursive or root-level chmod 777.",
	},
];

/**
 * Inspects serialized tool input (shell commands, inline Python, scripts)
 * for obfuscated or high-risk constructs prior to rule matching.
 */
export function analyzeToolInputStatic(toolName: string, rawInput: string): StaticRiskSignal[] {
	const signals: StaticRiskSignal[] = [];
	for (const p of SHELL_RISK_PATTERNS) {
		if (p.re.test(rawInput)) {
			signals.push({ code: p.code, severity: p.severity, detail: `[${toolName}] ${p.detail}` });
		}
	}
	return signals;
}
