# PATCHPROOF — Project Description

PATCHPROOF is a closed-loop application-security platform for demonstrating a stronger security workflow:

**Find → Prove → Patch → Replay → Regression → Patch Verified**

Unlike a scanner that only reports vulnerabilities, PATCHPROOF requires an exploit to be demonstrated and then replays that same attack after remediation. A fix is accepted only when the attack is blocked and normal application behaviour continues to pass regression tests.

## Components

- **Person 1 — Security Scanner:** discovers and proves SQL Injection and IDOR vulnerabilities against a deliberately vulnerable local application.
- **Person 2 — Remediation Engine:** applies deterministic patches, generates diffs, replays attacks, runs regression checks, and produces `PATCH_VERIFIED`.
- **Person 3 — Dashboard:** provides the live React interface for scanning, evidence, remediation, and verification.

## Core engineering idea

> A patch is not proof of a fix.  
> The original exploit must be replayed successfully against the patched application, and legitimate behaviour must still work.

The repository is intended as a hackathon/demo project and should only be used against systems for which testing is authorized.
