# ThreatIntel AI

An AI threat intelligence assistant for security operations teams, available directly in Discord.

ThreatIntel AI helps analysts answer the questions that come up during a shift: *Is this vulnerability being exploited? Should we worry about this IP address? Is this email really from who it claims to be? What happened in the threat landscape in the last few hours?* It answers with evidence, not guesses.

## Why it was built

Security teams lose time switching between vulnerability databases, vendor advisories, reputation services, and research blogs, then reconciling what each one says. General-purpose AI chatbots seem like a shortcut, but they answer confidently even when they are wrong: they invent severity scores, claim exploitation that never happened, and call an indicator "safe" because they found nothing.

In security work, a confident wrong answer is worse than no answer. ThreatIntel AI was built to give analysts the speed of a conversational assistant without that risk:

- Every fact comes from a source it actually checked, and says when it was checked.
- When sources disagree, it shows the disagreement instead of picking a side.
- When it does not know, it says so.
- Answers are checked against the evidence before they are sent.

It is tuned for a SOC protecting a **Bio/Pharma** organisation: lab systems, manufacturing and OT environments, and the security products such a team relies on.

## What it helps with

**Vulnerability questions.** Ask about any CVE and get its severity, whether it is known to be exploited, which products and versions are affected, and where fixes are available, with the source and date of every fact.

**Watchlist.** Choose the vulnerabilities that matter to your environment. The assistant keeps checking them and alerts the team when something meaningful changes, such as a new exploitation report, a severity change, or a newly released fix. It stays quiet otherwise.

**Threat feed.** Every three hours, the assistant reviews new advisories and research and posts only what is relevant and worth acting on, prioritised for the organisation. Each post names the threat, the affected products and platforms, a link to the original article, and any indicators of compromise to hunt for. When nothing new is worth posting, it says so and shares a short security concept instead.

**Alert triage.** Paste a whole alert, log excerpt, or email and every IP address, domain, URL, and file hash in it is checked at once, defanged or not. Results come back ranked by what the sources reported, with the ones to look at first on top, links to each record, and a clear list of what was not checked and why. Internal hostnames and private addresses are never sent outside.

**Indicator checks.** Paste an IP address, domain, URL, or file hash, defanged or not, and get its reputation from established threat intelligence services: whether it has been reported as malicious, whether it is a known benign service, and what is exposed on it. "No reports" is always reported as no reports, never as "safe".

**Email header analysis.** Paste the headers of a suspicious email to see whether it passed sender authentication, whether the sender, reply address, and display name are consistent, which server it came from, and what the sender's domain publishes. This is useful for phishing and business email compromise triage.

## How to use it

Mention the assistant in your team's channel and ask in plain language:

- `@ThreatIntel AI tell me about CVE-2024-3400`
- `@ThreatIntel AI has anything changed for CVE-2024-3400 since we last checked?`
- `@ThreatIntel AI triage this alert` (paste it, or attach it as a text file)
- `@ThreatIntel AI check 185.220.101[.]47`
- `@ThreatIntel AI look up hxxps://login-paypa1[.]com/verify`
- `@ThreatIntel AI analyse these email headers` (paste them or attach them as a text file)

Threat feed posts and watchlist alerts arrive in their own channels automatically.

## Principles

- **Evidence first.** Facts come from checked sources, never from the AI's memory. Each answer shows where a fact came from and when.
- **No false reassurance.** An indicator with no reports is "not reported", not "clean". An email that passes authentication is shown to come from its domain, not declared legitimate.
- **Checked before sending.** Answers that contradict the evidence, such as a misquoted score or a result from a source that was not checked, are corrected or flagged before they reach you.
- **Privacy by default.** Private and internal addresses are never sent outside the organisation. Email recipients are never shown, and pasted email headers are not stored. Names, accounts, email addresses, internal hosts and phone numbers in what you paste are replaced with placeholders before anything reaches the AI model, and passwords or keys are removed entirely; the real values appear only in the reply in your own channel.
- **Confidential by design.** The assistant does not discuss how it is built or configured, and it never asks for passwords or API keys. Do not paste credentials into chat.

## Access

ThreatIntel AI is a private, internal tool. Access is granted by invitation to the team's Discord server. For access, questions, or feedback, contact the project owner.

## License

Proprietary. Copyright © 2026. All rights reserved. This project is not open source; no part of it may be copied, modified, or distributed without permission.
