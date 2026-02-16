# OpenClaw Codebase Review
**Date:** February 15, 2026
**Version Reviewed:** 2026.2.15


## Legal Disclaimer
**"This technical research and review is for educational purposes on public code and constitutes Fair Dealing under the Copyright Act (Canada)."**

## Executive Summary
OpenClaw describes itself as a "labor of love" and a "multi-channel AI gateway." While it is a functional and extensible platform, it carries **significant security and reliability risks** that users must be aware of. It is **not suitable for public internet exposure** and relies heavily on external, opaque dependencies for its core agentic logic.

## 1. Security Analysis

### 🚨 Critical Vulnerability: Malicious Skills 
*   **Mechanism**: The "Skill" system allows the installation of folders containing `scripts/` (Python, Bash, etc.) and `SKILL.md` definitions.
*   **Risk**: These scripts are executed by the agent.
*   **Public Skill Risks**:
    *   **No Safety Net**: There is no central, vetted "App Store". "Public skills" are just folders of code you download from GitHub or the community.
    *   **Supply Chain Attacks**: Skills often use `pip`, `npm`, or `brew` to install dependencies. A malicious skill can pull in a compromised package or run `curl | bash` during installation.
    *   **Zero Isolation**: Since safeguards are weak (see below), a bad skill has the same access rights as the user running OpenClaw.
*   **Real-World Scenarios**:
    *   **The "Typosquatting" Attack**: A skill asks to install a python dependency `reqeusts` (misspelled `requests`). This malicious package installs a backdoor on your system. This is a common attack vector on PyPI/npm.
    *   **The "SSH Stealer"**: A simple "Productivity Skill" contains a `postinstall` script in its `package.json` that uploads your `~/.ssh/id_rsa` file to a remote server. OpenClaw executes this script automatically during installation.
    *   **The "Crypto Miner"**: A "Stock Analysis" skill installs a background worker that mines Monero using your CPU, disguised as a "data processing" task.

### 🕵️ Deep Research Confirmation (New Intelligence)
A separate technical analysis confirms active exploitation of these risks:
*   **"ClawHavoc" (Jan 2026)**: Attackers distributed 335 malicious skills (e.g., `solana-wallet-tracker`) that installed "Atomic Stealer" malware. **12% of the entire skill registry was compromised.** (https://www.reco.ai/blog/openclaw-the-ai-agent-security-crisis-unfolding-right-now)
*   **"Moltbook" Breach (Feb 2026)**: A related social network database leaked **1.5 million agent tokens** and 35,000 user emails, proving the ecosystem's lack of security maturity. (https://www.reco.ai/blog/openclaw-the-ai-agent-security-crisis-unfolding-right-now)
*   **Cost Explosion**: Gateway restart or AbortError triggers a loop where OpenClaw retries the entire LLM run multiple times. This re-sends the full session context (often 100k+ tokens) to the API (e.g., Claude Opus) repeatedly, causing a rapid spike in costs. (https://github.com/openclaw/openclaw/issues/17589). This led to "massive context bloat," causing session files to grow unbounded and filling the context window with useless schema definitions, which indeed caused users to burn through credits the inflated context was sent with every request. (https://github.com/openclaw/openclaw/issues/6650)
*   **Public Exposure (Censys Data)**: Deep research confirmed on the public internet, many leaking API keys and tokens due to insecure defaults. (https://thehackernews.com/2026/02/openclaw-integrates-virustotal-scanning.html)

### 💣 The "Time Bomb" Risk: Why You Don't Feel It Yet
**No.** In modern cybercrime, immediate theft is rare. Attackers play the long game:
1.  **Token Hoarding**: Attackers collect millions of stolen GitHub/OpenAI tokens (like the 1.5M from Moltbook) and sit on them.
2.  **The "Bomb"**: They wait for a high-value event (e.g., a new model launch, a holiday crypto spike) to sell access to these tokens in bulk on the dark web.
3.  **The Result**: One day, months from now, your API bill hits $5,000 in an hour, or your WhatsApp account spams all your contacts with a crypto scam. You won't know you were hacked until it's too late.
4.  **Persistent Access**: Stolen SSH keys or authenticated session files (WhatsApp `auth_info_baileys`) bypass 2FA. Changing your password often **does not invalidate** these stolen session tokens.


### 🧠 PI-CORE Code Audit (The "Hidden Brain")
I checked the core packages (`pi-agent-core`, `pi-ai`, `pi-coding-agent`) that drive the logic:
*   **Quality**: The code is highly professional, event-driven, and type-safe. This is not amateur work.
*   **No Defensive Depth**: `agent-loop.ts` blindly executes whatever tool the LLM asks for. There is **zero sandboxing** at the core level.
*   **Package Manager Risk**: `pi-coding-agent/src/core/package-manager.ts` allows the agent to `npm install` or `git clone` anything it wants. If an agent is tricked into installing a malicious package, it executes in the host environment immediately.

### 🦠 Lateral Movement: The "Typhoid Mary" Risk
**Yes.**
*   **Mechanism**: Since OpenClaw runs with the user's full shell privileges on the host, a compromised agent can run `nmap`, `ssh`, or `curl`.
*   **Attack Vector**:
    1.  Agent gets infected via a malicious skill (e.g., `solana-wallet-tracker`).
    2.  Malware scans your local network (192.168.1.x) for other devices.
    3.  It attacks your **NAS (Synology)**, **Partner's Laptop**, **Smart TV**, or **printer** whether they are on **Wi-Fi or Ethernet**.
    4.  Your "safe" local server becomes the **Patient Zero** that infects your entire home or office network.

### 🏗️ Architectural Verdict: "No Security by Design"

**Recommendation: DO NOT PROCEED.**

1.  **The "Hidden Brain" Risk**: OpenClaw depends on `PI-CORE` (`@mariozechner/pi-*`), which is **not** in the main repository. I had to perform extra work to find and review this code. Relying on a massive, external, unversioned "brain" is a critical supply chain risk.
2.  **The "Local Only" Fallacy**: The architecture assumes "Local Network = Safe." This is false. A single malicious "Skill" or a browser exploit (CSRF) can bridge the gap from the internet to your local agent.
3.  **Regressions & Stability**: With 3,200+ open issues, every fix seems to introduce new loopholes. The testing matrix is insufficient for a tool with this level of privilege (Full Disk Access, Shell Access).

**Conclusion**: The lack of a defined security boundary makes this tool fundamentally unsafe for production or personal use with sensitive data.

### 🎭 Security "Theater" & Out-of-Scope Risks
The `SECURITY.md` explicitly excludes two massive meaningful attack vectors from its threat model:
1.  **Prompt Injection**: Marked **"Out of Scope"**. This means the developers acknowledge that the agent can be tricked into performing actions it shouldn't, but they do not consider this a reportable vulnerability.
2.  **Public Exposure**: Marked **"Out of Scope"**. This is a critical distinction that many users miss.
    *   **Localhost only (127.0.0.1)**: The software is designed to run here. It assumes the only person moving the mouse is *you*.
    *   **Local Network (LAN)**: Binding to `0.0.0.0` allows other devices on your Wi-Fi to access the control panel. This is risky if your network is not perfectly secure (guest Wi-Fi, compromised IoT devices).
    *   **Public Internet (WAN)**: **DO NOT DO THIS.** If you forward ports on your router to OpenClaw, you are exposing an interface with **no defense in depth** to the entire internet. It lacks the rate-limiting, CSRF protection, and hardened authentication required for public-facing servers. "Out of scope" means: if you do this and get hacked, the developers will simply say "we told you so."
*   **Source Evidence**: `SECURITY.md` (Out of Scope section); `src/gateway/server.impl.ts` (Default bind to 127.0.0.1)

### 🐛 Authentication Issues
*   **Missing Scopes**: Users report `operator.admin` scope errors in the Control UI. Our review indicates complex scope checks in `src/gateway/server.impl.ts`. The error likely stems from a mismatch between the UI's requested tokens and the backend's enforcement, leading to broken access control even for legitimate interaction.
*   **Source Evidence**: `src/gateway/server.impl.ts` (Scope verification logic)

### 🏴‍☠️ Security Risks: Unofficial Messaging Integrations
*   **WhatsApp (Ban Risk & Privacy)**:
    *   **Mechanism**: Uses `@whiskeysockets/baileys` to emulate a web client, not the official API.
    *   **Security Risk**: Session keys are stored locally. If your machine is compromised, the attacker has full access to your WhatsApp account.
    *   **Ban Risk**: This violates WhatsApp ToS. Meta actively bans accounts using unauthorized clients.
    *   **Source Evidence**: `package.json` (dependency on `baileys`).
*   **iMessage (Total System Compromise)**:
    *   **Mechanism**: Relies on a local CLI (`imsg`) reading the `chat.db` file.
    *   **Security Risk**: Requires granting **Full Disk Access** to the terminal/app. This breaks the sandbox entirely. Any malicious skill running in OpenClaw now has read access to your *entire filesystem*, not just messages (Photos, Mail, Documents).
    *   **Fragility**: An Apple OS update can break this integration instantly.
    *   **Source Evidence**: `src/channels/plugins/onboarding/imessage.ts` (Requirement for Full Disk Access).
    *   **Official Documentation**: `docs.openclaw.ai` explicitly requires enabling **Accessibility**, **Screen Recording**, **Camera**, and **Microphone** permissions, effectively granting the agent total surveillance power over your system.

### 🤖 Unofficial Model Support (Subscription Hijacking)
OpenClaw supports using "Pro/Ultra" subscription plans instead of API credits in two ways:
1.  **GitHub Copilot (Native)**:
    *   **Mechanism**: `src/providers/github-copilot-auth.ts` implements the GitHub Device Flow. It mimics a VS Code client to obtain a token.
    *   **Effect**: Allows using LLMs (via Copilot) using your $20/mo GitHub subscription, bypassing API costs.
    *   **Risk**: High probability of violating GitHub ToS if used for general agent automation.
2.  **Browser Bridge (Infrastructure)**:
    *   **Mechanism**: `src/browser/extension-relay.ts` sets up a WebSocket server to relay data from a Chrome Extension.
    *   **Effect**: This is the plumbing required to hijack a "ChatGPT Web" or "Claude Web" session and use it as an API. While no bundled skill explicitly does this, the capability is built into the core.
3.  **Assessment: Are they legit?**
    *   **No.** Using a "human" subscription for **automated agentic work** is a violation of the Terms of Service for almost every provider.
    *   **Consequences**:
        *   **Account Ban**: GitHub/OpenAI/Anthropic can and will ban your account permanently.
        *   **Enterprise Risk**: If you do this with a corporate GitHub account, you could get your entire company's organization flagged for abuse.

### ⚖️ Ethical Concerns: Official Recommendations

*   **Finding**: The `README.md` and `openclaw onboard` command explicitly recommend "Subscriptions (OAuth)" for Anthropic and OpenAI. The official documentation explicitly mentions using 'Claude Pro/Max' or 'ChatGPT' subscriptions via OAuth for this agent. WARNING: These are consumer subscriptions intended for human interaction. OpenClaw is an automated system that can generate massive volumes of traffic (retries, cron jobs, context bloat). Connecting an automated agent to a consumer subscription is a violation of OpenAI and Anthropic Terms of Service and puts your personal account at high risk of immediate termination/banning. The documentation's recommendation to use these accounts is dangerous advice for new users.
*   **Reality**: Standard API usage is not a "Subscription". The project uses this terminology and provides tools (`claude setup-token`) that likely emulate consumer clients.
*   **Assessment**:
    *   They are guiding users—especially beginners—into a "Ban Trap".
    *   They do not provide sufficient warning in the onboarding flow about the risks of using consumer accounts for agentic automation.
    *   It conflates "Open Source Freedom" with "Freedom to exploit service terms," putting the end-user at risk.

### ✅ Positive Findings
*   **RCE Patch**: The project recently patched CVE-2026-25253 (RCE) in version 2026.1.29. (https://www.runzero.com/blog/openclaw/).  The current version (2026.2.15) includes this fix.
*   **Source Evidence**: `CHANGELOG.md` (Version 2026.1.29 entry regarding "Gateway auth mode 'none' is removed")
*   **Environment Hardening**: `src/agents/bash-tools.exec-runtime.ts` actively blocks dangerous environment variables (`LD_PRELOAD`, `NODE_OPTIONS`) to prevent simple privilege escalation or injection attacks during command execution.
*   **Source Evidence**: `src/agents/bash-tools.exec-runtime.ts` (`validateHostEnv` function)

## 2. Code Quality & Architecture

### 📦 "Open" Source?
*   **External Core**: A significant portion of the intelligent logic resides in external dependencies:
    *   `@mariozechner/pi-agent-core`
    *   `@mariozechner/pi-ai`
    *   `@mariozechner/pi-coding-agent`
    These packages are **not present in the repository**. If they are closed-source or unverified, "OpenClaw" is effectively a runner for a black-box brain.
*   **Source Evidence**: `package.json` (dependencies list)

### 🕸️ Complexity & Debt
*   **Issues Count**: 3,000+ open issues indicate a project that might be overwhelmed.
*   **Dependency Sprawl**: The `extensions/` directory bundles over 30+ integrations (Feishu, WeChat/WeCom, Line, Matrix, etc.), each potentially pulling in unaudited 3rd-party libraries.
*   **Source Evidence**: `extensions/` directory and `package.json` dependencies like `larksuiteoapi`, `line-bot-sdk`, `matrix-sdk-crypto-nodejs`.
*   **Fragility**: Reports of "Cron job WhatsApp delivery intermittently fails" and "Memory flush writes files with wrong year" point to subtle bugs in the `src/cron/` and state management modules.
*   **Source Evidence**: `CHANGELOG.md` (Multiple fixes for Cron and Memory reliability in recent versions)

### 🛡️ Legal & Liability (MIT License)
*   **Who is responsible?** YOU ARE.
*   **The License**: The project uses the standard MIT License.
*   **"AS IS" Clause**: The software is provided "as is", without warranty of any kind.
*   **The Reality**:
    *   If OpenClaw is **hacked** and attacks your local network: **You are liable.**
    *   If OpenClaw hallucinates and deletes your files: **You are liable.**
    *   If a bug causes it to loop and burn **$5,000 in OpenAI API credits**: **You are liable.**
    *   The authors explicitly disclaim all liability.
*   **Source Evidence**: `LICENSE` file (Lines 15-21).

## 3. Industry Standards Benchmarking

**Yes.** The two most prominent frameworks are the **Open Worldwide Application Security Project (OWASP) Top 10 for LLM Applications** and the **NIST AI Risk Management Framework**.

OpenClaw fails to meet the basic requirements of both:

### OWASP Top 10 for LLM (2025 Edition)
**Reference:** [OWASP Top 10 for LLM Level 1.1 Checklist](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)

| OWASP Risk | Description | OpenClaw Status |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Attackers manipulating the LLM to ignore instructions. | **FAILED**: Explicitly listed as "Out of Scope" in `SECURITY.md`. |
| **LLM02: Sensitive Info Disclosure** | Leaking secrets or PII. | **FAILED**: Stores secrets in plain text `.env` and unencrypted session files. |
| **LLM03: Supply Chain** | Compromised third-party components (Plugins/Skills). | **FAILED**: The "Skill" system installs unvetted code from arbitrary URLs with no signature verification. |
| **LLM06: Excessive Agency** | Granting LLMs too much power (e.g., shell access) without approval loops. | **FAILED**: The core design gives the agent **Full Disk Access**, **Shell Access**, and **Auto-Execution** capabilities. |
| **LLM05: Improper Output Handling** | Executing code generated by the LLM without validation. | **FAILED**: `bash.ts` executes arbitrary commands directly on the host. |

### NIST AI RMF (Risk Management Framework)
*   **Map**: OpenClaw fails to map risks to downstream impacts (e.g., lateral movement).
*   **Measure**: No metrics for toxicity, hallucination rate, or security failures.
*   **Manage**: No incident response plan for compromised skills or agents.

**Verdict**: OpenClaw operates in direct contradiction to established AI safety standards.

## 4. Recommendations

*   **Do NOT expose to the internet.** Use Tailscale or SSH tunnels only.
*   **Audit every Skill.** Treat every downloaded skill as a potential malware dropper. Read the `scripts/` folder before installing.
*   **Run in Docker.** Ensure you are forcing the `sandbox` host mode. Do not run the "macOS desktop app" directly on your daily driver machine if you plan to install community skills.

### ✅ Verification & Evidence (Fact-Check)
1.  **Unrestricted Shell Access**: Verified in `pi-coding-agent/src/core/tools/bash.ts` (lines 58-73). The agent uses `child_process.spawn` to execute *any* command you request, with your user permissions.
2.  **"Patient Zero" Risk**: Confirmed by `bash.ts`. Since it has full shell access, it can execute `nmap`, `ssh`, or `curl` against any device on your local network (Wi-Fi or Ethernet).
3.  **Subscription Risk**: Verified in `README.md` (lines 33-38). The docs explicitly recommend using "Claude Pro/Max" or "ChatGPT" subscriptions via OAuth, which puts personal accounts at risk of bans for automated usage.
4.  **Security "Out of Scope"**: Verified in `SECURITY.md` (lines 46-50). "Prompt injection" and "Public Internet Exposure" are explicitly listed as out of scope.

### 🏁 Final Recommendation
The architectural flaws ("Glass Cannon" core, lack of sandboxing, and full shell access) make it too dangerous for personal or professional use.
