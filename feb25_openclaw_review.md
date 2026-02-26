# OpenClaw Security & Reliability Review (Feb 2026)
**Date:** February 25, 2026
**Version Reviewed:** 2026.2.25


## Legal Disclaimer
**"This technical research and review is for educational purposes on public code and constitutes Fair Dealing under the Copyright Act (Canada)."**

## Executive Summary
This document summarizes our security and reliability findings for the OpenClaw architecture based on the provided initial review and subsequent code verification. A subsequent analysis of the project's `VISION.md` confirms that these architectural vulnerabilities are not oversights, but rather explicit design choices. The maintainers heavily prioritize "hackability" and local capabilities over enterprise-grade security isolation. Consequently, the findings confirm that OpenClaw, in its current state, poses significant risks if exposed to the public internet, used on a local network without strict isolation, or operated using consumer subscription tiers for automated agentic behavior.

**Disclaimer:** Please note that this review does not represent a complete or exhaustive list of all possible security issues, loopholes, or bugs. This report is strictly based on a point-in-time technical analysis of the existing open-source code, repository metadata, and official documentation as of February 25, 2026.

## Verified Findings

### 1. External Core Dependency & Supply Chain Risk
**Files Verified:** `package.json`  
*Non-Technical Summary: The core intelligence logic of this tool resides in external packages built by third parties. If one of these external dependencies is compromised, the tool would automatically execute the affected version, posing a risk to the host system.*
OpenClaw relies heavily on unvendored, exterior core packages (`@mariozechner/pi-agent-core`, `@mariozechner/pi-coding-agent`, `@mariozechner/pi-ai`). The core cognitive architecture and tool execution handling reside outside this repository. This introduces a substantial supply chain attack surface and makes it difficult to guarantee the integrity of the agent's core decision loop over time, as it is a moving target. 

### 2. Local Network Lateral Movement Risks
**Files Verified:** `src/gateway/server.impl.ts`, `src/agents/bash-tools.exec-runtime.ts`  
*Non-Technical Summary: When active, this tool exposes a network port. If configured incorrectly, anyone on the same Wi-Fi network could connect to it, meaning unauthorized users on the same network could potentially execute commands on the host machine.*
The gateway server includes logic to bind to `0.0.0.0` (LAN). While the `bash-tools.exec-runtime.ts` does implement logic to sanitize the host environment (e.g., stripping `$PATH` overrides or dangerous variables), agents ultimately execute un-sandboxed Node/Bash logic on the host by default. Real isolation is only achieved if strictly configured to use a Docker sandbox mode. If an agent is compromised or exposed, it has broad access to the local network and the deployment environment.

### 3. Deliberately Out-of-Scope Security Policies
**Files Verified:** `SECURITY.md`  
*Non-Technical Summary: The maintainers explicitly state that prompt injection and public internet exposure are outside their threat model. The tool is designed exclusively for single-user, trusted-network deployments and does not natively protect against these modern AI attack vectors.*
The maintainers have explicitly scoped out critical modern threats for LLM integrations. Specifically, "Prompt Injection" and "Public Internet Exposure" are listed as out of scope. This confirms that OpenClaw operates on a strict "One-User Trust Model" and is explicitly not designed to be a public-facing service.

### 4. Excessive File System Access (iMessage Plugin)
**Files Verified:** `src/channels/plugins/onboarding/imessage.ts`  
*Non-Technical Summary: Enabling the iMessage integration requires granting 'Full Disk Access'. This gives the agent unbounded read capabilities across the macOS filesystem, significantly increasing the potential impact of an exploit or prompt injection attack.*
The iMessage onboarding sequence requires the user to manually grant OpenClaw "Full Disk Access" and "Automation permissions" to the Messages database on macOS. This represents a massive privacy and security tradeoff, essentially granting the agent unbounded filesystem reads which could be exploited if the agent goes rogue or is injected.

### 5. Terms of Service & Subscription Hijacking Risks
**Files Verified:** `src/providers/github-copilot-auth.ts`, `README.md`  
*Non-Technical Summary: Automating activity through personal accounts violates most provider Terms of Service. This risks account suspension and creates a scenario where an exploit could compromise the user's subscription access.*
The `github-copilot-auth.ts` implements a standard OAuth device code flow to leverage GitHub Copilot. Furthermore, the `README.md` explicitly recommends using consumer model subscriptions like "Anthropic Pro/Max (100/200) + Opus 4.6" for best performance. Automating traffic through personal consumer subscriptions typically violates provider Terms of Service (ToS) and risks account suspension, rate limits, or potential hijacking of that subscription state.

### 6. Cost Explosion & Context Bloat via Infinite Looping
**Files Verified:** `src/agents/pi-embedded-runner/run.ts`, `src/agents/compaction.ts`  
*Non-Technical Summary: Because LLM API usage is billed by token volume, an agent stuck in an automated retry loop could silently generate runaway API costs.*
There is confirmed evidence of mechanisms that can cause severe cost overruns. The primary execution loop in `run.ts` runs inside a `while (true)` loop with a maximum iteration count defined by `MAX_RUN_RETRY_ITERATIONS` (typically between 32 and 160 iterations, depending on profile candidates). Furthermore, there is auto-compaction logic (`compactEmbeddedPiSessionDirect`) to aggressively summarize overflowing context. While this attempts to prevent hard crashes, the massive retry loop combined with the continuous summarization allows an agent to silently burn through hundreds of thousands of tokens (and thus high costs) when stuck in an unproductive failure loop.

### 7. SECURITY.md Differential Analysis (Feb 15 vs. Feb 25)
**Files Verified:** `feb15-2026-review/SECURITY.md`, `SECURITY.md`  
*Non-Technical Summary: Recent updates to `SECURITY.md` reclassify several reported structural vulnerabilities as "Out of Scope" or "False Positives." This formalizes the project's stance that these risks are accepted deployment assumptions rather than software defects.*
A differential analysis between the older (Feb 15) and current (Feb 25) versions of `SECURITY.md` reveals a distinct pattern: rather than mitigating the reported structural vulnerabilities through code execution changes, the maintainers have significantly expanded the security policy to formally classify them as "Out of Scope," "False Positives," or expected behavior under their trust model.

Key additions include:
*   **Report Acceptance Gate & False Positives**: Added strict triage requirements and a large block of "Common False-Positive Patterns" that formally dismiss reports involving malicious plugins, ReDoS/DoS via config inputs, prompt-injection chains, and intra-gateway multi-tenant isolation as out of scope.
*   **Operator Trust Model (Important)**: Explicitly codified the "One-User Trust Model," stating that a single gateway is *not* a multi-tenant boundary. Authenticated callers are completely trusted operators, meaning any lateral movement they achieve is considered authorized.
*   **Trusted Plugin Concept (Core)**: Added a section explicitly defining plugins as part of the "trusted computing base." Plugins run in-process and are granted the same privileges as OpenClaw itself, confirming that the architecture provides zero isolation for third-party skills.
*   **Expanded Out-of-Scope Rules**: Added rules explicitly rejecting reports that rely on adversarial operators sharing a gateway, reports requiring write access to the workspace memory (`MEMORY.md`), and reports detailing host-side arbitrary execution when sandboxing is disabled.

This differential confirms that the maintainers are aware of these structural risks but have chosen to reclassify them as accepted deployment assumptions rather than security flaws.

### 8. README.md Differential Analysis (Feb 15 vs. Feb 25)
**Files Verified:** `Feb15-2026-review/README.md`, `README.md`  
*Non-Technical Summary: Explicit mentions of using personal Anthropic (Claude) subscriptions and the "BlueBubbles" (iMessage) integration were removed from the main documentation, possibly to deter unsupported configurations or mitigate ToS violations. However, code review confirms the underlying functionality remains fully active.*  
A differential analysis between the older (Feb 15) and current (Feb 25) versions of `README.md` reveals a few key operational changes that correlate with our risk findings. Rather than removing the underlying functionality, the maintainers appear to be scrubbing explicit endorsement from the documentation:

*   **Omission of Anthropic OAuth**: The Feb 15 README explicitly listed **Anthropic (Claude Pro/Max)** as a supported OAuth subscription. In the Feb 25 version, Anthropic has been removed from the "Subscriptions (OAuth)" list entirely, though a note recommending Claude Pro/Max still remains below it. This omission removes the explicit endorsement of a flow that typically violates consumer Terms of Service, though the underlying OAuth logic remains in the codebase. (Code review of `src/agents/pi-embedded-runner/extra-params.ts` confirms Anthropic OAuth logic is still present).
*   **Omission of BlueBubbles (iMessage) Channel**: The Feb 15 version explicitly listed `BlueBubbles (iMessage, recommended)` in the Channels list. In the Feb 25 version, this explicit mention is gone, leaving only the legacy `iMessage` integration. This indicates an attempt to obscure or de-emphasize the highly privileged integrations that require Full Disk Access without actually removing the underlying capability from the codebase. (Code review of `src/channels/plugins/status-issues/bluebubbles.ts` confirms the BlueBubbles plugin is still fully intact).
*   **Documentation Refactoring**: Several URL routes were changed (e.g., `/concepts/group-messages` to `/channels/group-messages`), indicating an ongoing internal restructuring of how they categorize "Channels" versus core "Concepts," likely pointing to the plugin boundary issues highlighted in finding #3.
### 9. OWASP Top 10 for LLMs (v2.0) Compliance Failure Mapping
**Reference Standard:** `LLMAll_en-US_FINAL.pdf` (OWASP Top 10 for LLM Applications v2.0)

Based on the source code review and documented architectural tradeoffs, OpenClaw fundamentally fails against several critical categories of the OWASP Top 10 for LLMs:

*   **[LLM01:2025] Prompt Injection (FAIL):** 
    *   **Evidence:** `SECURITY.md` explicitly lists "Prompt-injection-only attacks" as Out of Scope. OpenClaw relies entirely on underlying LLM providers (e.g., Anthropic Opus 4.6 as noted in `README.md`) to resist injection, providing no ingress sanitization or structural control layer within the gateway itself.
*   **[LLM02:2025] Sensitive Information Disclosure (FAIL):**
    *   **Evidence:** The gateway binds to `0.0.0.0` (LAN) per `src/gateway/server.impl.ts`, exposing the agent and potentially its active memory routing to local network traffic. Moreover, the iMessage plugin (`src/channels/plugins/onboarding/imessage.ts`) demands Full Disk Access, unnecessarily exposing the host's entire file system to a potentially compromised agent.
*   **[LLM03:2025] Supply Chain (FAIL):**
    *   **Evidence:** The core cognitive logic is abstracted out to remote, unvendored NPM packages like `@mariozechner/pi-agent-core` (`package.json`), meaning a compromised upstream publisher account instantly pushes malicious updates to the gateway's "brain."
*   **[LLM04: Data and Model Poisoning] (NOT APPLICABLE):**
    *   OpenClaw acts as an orchestration layer connecting to external API providers (OpenAI, Anthropic). It does not natively train or fine-tune models on local data.
*   **[LLM05:2025] Improper Output Handling (CRITICAL FAIL):**
    *   **Evidence:** The agent takes LLM-generated text and executes it natively as bash scripts on the host operating system (`src/agents/bash-tools.exec.ts`, `src/agents/bash-tools.exec-runtime.ts`). OpenClaw trusts the model's output to formulate safe shell commands without enforcing a mandatory downstream sandbox validation by default.
*   **[LLM06:2025] Excessive Agency (CRITICAL FAIL):**
    *   **Evidence:** `VISION.md` dictates that all plugins run in-process without sandboxing, inheriting the host's OS privileges. This grants the LLM agent excessive capabilities and massive, unchecked autonomy during automated execution loops.
*   **[LLM07:2025] System Prompt Leakage (NOT APPLICABLE):**
    *   OpenClaw is an open-source tool. The system prompts and tool schemas are public by design, meaning their disclosure poses no inherent security risk to the platform itself.
*   **[LLM08:2025] Vector and Embedding Weaknesses (UNVERIFIED):**
    *   The project uses local memory plugins (`MEMORY.md`), but evaluating the exact vector storage implementation is outside the scope of this architectural surface review.
*   **[LLM09:2025] Misinformation (NOT APPLICABLE):**
    *   This is a risk inherited directly from the downstream LLM provider (e.g. Anthropic/OpenAI) rather than a flaw in the OpenClaw orchestration architecture.
*   **[LLM10:2025] Unbounded Consumption (FAIL):**
    *   **Evidence:** `src/agents/pi-embedded-runner/run.ts` executes an unconstrained `while (true)` loop bounded only by an excessively high `MAX_RUN_RETRY_ITERATIONS`. In failure states, `src/agents/compaction.ts` continually resizes the context to keep looping, creating a mechanism capable of generating massive token usage during looping failure states and requiring users to rely on provider-side billing limits.

### 10. Anomalous Issue Triage Velocity (Feb 15 - Feb 25)
**Data Source:** GitHub Repository Search Statistics
*Non-Technical Summary: Between February 15 and 25, the developers manually closed 3,741 bug reports—over 42% of all bugs ever closed in the project's history—without using standard cleanup bots or formal triage tags. Additionally, while their own changelog lists dozens of "Security" patches, they only officially labeled 3 code changes as security-related. This data suggests a rapid administrative closure of the backlog alongside a focus on specific, targeted security patches, while broad architectural changes appear to be deprioritized.*

Repository search metrics provided for the window between February 15 and February 25, 2026, reveal an unprecedented triage velocity:
*   **Total Issues Closed in 10 Days:** 3,741
*   **Total Issues Closed All-Time (as of Feb 25):** 8,839
*   **Total PRs Merged in 10 Days:** 735

**Deeper Search Analysis:**
Further queries into the repository's metadata reveal critical anomalies regarding *how* these 3,741 issues were closed:
1.  **No Administrative Bots:** `is:issue is:closed closed:2026-02-15..2026-02-25 author:app/github-actions` returned **0 results**. This indicates the closures were performed manually rather than through routine automated maintenance.
2.  **No Standard Triage Labels:** `label:"wontfix"` (and presumably similar tags) returned **0 results**. They did not formally tag these closures, avoiding standardized reporting metrics.
3.  **Obfuscated Security PRs:** `is:pr is:merged merged:2026-02-15..2026-02-25 label:security` returned only **3 results**. However, the project's own `CHANGELOG.md` for this period contains dozens of bullet points prefixed with `Security/` (for example, patching sandbox symlink escapes and webhook vulnerabilities). 

**Conclusion on Triaging:**
Closing 3,741 issues manually accounts for ~42.3% of the repository's total lifetime closed issues. Given the concurrent changes made to `SECURITY.md` (Finding #7) which introduced strict new "Report Acceptance Gates" and "Common False-Positive Patterns," there is a strong potential correlation. 

This volume of manual closures, concurrent with the `SECURITY.md` update, indicates a massive administrative clearing of the backlog, aligning with the newly documented 'Out of Scope' definitions and triage gates. The merging of unlabeled security patches indicates ongoing remediation efforts that are not officially tracked via the `security` PR label.

Furthermore, the high feature velocity (735 PRs merged in 10 days, averaging over 73 PRs merged per day) indicates a fast-moving development environment focused heavily on rapid feature iteration. During this exact 10-day window of heavy backlog closure, the project deployed massive new capabilities including a fully Native Android Application, a comprehensive UI overhaul for automated "Cron" scheduling, new voice/text "panic button" abort shortcuts, and a built-in package auto-updater. 

For prospective enterprise users, this velocity pattern—shipping complex new architectural surfaces while simultaneously deprecating historical vulnerability reports via policy updates—reinforces the conclusion that stability and rigorous security isolation are currently secondary to raw feature shipping.

### 11. Limitations of VirusTotal Partnership
**Code/Resource Reference:** `https://openclaw.ai/blog/virustotal-partnership`
*Non-Technical Summary: The project recently announced a partnership with VirusTotal to scan third-party "Skills" (plugins) for malware before users download them. While this provides code-level scanning, the developers explicitly acknowledge that this scanning "won't catch everything," noting that malicious instructions given in natural language won’t trigger a virus signature. Because plugins operate with full system access (Finding #8), this scanning mechanism does not mitigate the primary threat of natural language manipulation (prompt injection).*

On February 7, 2026, the OpenClaw team published a blog post announcing a partnership with VirusTotal to provide "Code Insight" security scanning for all skills published to ClawHub. The integration automatically approves skills with a "benign" verdict.

While scanning third-party code for known command-and-control signatures or stealers is a positive step, the blog post itself contains a critical admission regarding the limits of this approach for LLM agents:
> *"VirusTotal scanning won’t catch everything. A skill that uses natural language to instruct an agent to do something malicious won’t trigger a virus signature. A carefully crafted prompt injection payload won’t show up in a threat database."*

**Analysis:**
While the partnership introduces valuable static code analysis, the promotion of an "Auto-Approval" system may lead users to overestimate the platform's overall security posture. 

Because OpenClaw still adheres to an architecture where plugins run *in-process* with full host OS privileges (see Finding #8 and `VISION.md`), any skill that bypasses the VirusTotal scan—whether via obfuscation or, more likely, via natural language manipulation (prompt injection) as admitted by the authors—has immediate, unfettered access to the user's local filesystem and network. The VirusTotal integration scans the *code*, but fails to sandbox the *execution*, leaving the core prompt-injection vulnerability largely unmitigated.

## Conclusion
Our analysis of the codebase, documentation (`SECURITY.md`), and project doctrine (`VISION.md`) paints a consistent picture: OpenClaw is fundamentally engineered as a powerful local assistant prioritizing utility, rather than a secure, multi-tenant enterprise application. 

The security posture of OpenClaw inherently relies on the following explicit structural tradeoffs:
*   **The Deployment Environment is the Perimeter:** The project acknowledges a "One-User Trust Model," meaning there is no internal multi-tenant authorization boundary. The user is entirely responsible for standing up network segmentation and mandatory Docker-based sandboxing.
*   **Plugins Inherit Host Access:** The project's architecture dictates that all optional capabilities ship as plugins, and that those plugins execute in-process with the same OS privileges as the OpenClaw host. This means any installed skill effectively operates outside of the Docker bash sandbox by design.
*   **Decentralized Core Logic:** The reliance on exterior npm packages and external sidecar processes (like `mcporter` for MCP) expands the supply chain attack surface and makes it highly difficult to rigorously verify the core decision loop.

Using OpenClaw safely in any capacity outside of a single-user, fully trusted, local-only environment requires aggressive network segmentation, strict access controls, and enterprise-grade API keys rather than consumer accounts.
