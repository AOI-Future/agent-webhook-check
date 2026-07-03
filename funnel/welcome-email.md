# Substack Welcome email — free subscribers (dispatch.aoifuture.com)

Receiving-end of the webhook-check lead-magnet funnel. The tool is already a
**public** repo, so this email does not gate a download — it (1) confirms the
subscribe, (2) re-hands the tool, (3) sets the "next free case" expectation,
(4) seeds the free book (1F) and the paid kit (2F).

Set at: Substack → Settings → Emails → **Welcome email to free subscribers** → Edit.

---

## Subject

Your webhook-check link — and what the dispatch sends next

## Body

Thanks for subscribing to **Aoifuture Dispatch**.

You came for **webhook-check** — the free, single-file auditor for the webhook
signature verifiers that sit under your agent's tool callbacks. Here it is:

→ **https://github.com/AOI-Future/agent-webhook-check**

See it find a real forged-signature bug in ten seconds:

```
python3 webhook_check.py --demo
```

Then point it at your own verifier — no deps, no network, stdlib only:

```
python3 webhook_check.py --verifier yourmodule:verify
```

Exit `0` = every check passed, `1` = at least one failed, so it drops straight
into CI.

**What I'll send you next (the Security thread):**

- The next free case as I carve it out of the full kit.
- A heads-up when the standards move — MCP server pinning, Enterprise-Managed
  Authorization (EMA).

**If you need the whole surface — with evidence you can defend:**

- **The field manual — _AI Agent Security_** — what to verify across the agent
  attack surface, and why. Free with a Leanpub membership (or name your price):
  https://leanpub.com/agent-security
- **The AI-Agent Security Verification Kit** — every check in one command,
  sealed into a single JSON + PDF artifact whose hash is countersigned by an
  RFC 3161 timestamp authority. Proof of *what* you tested and *when*; no secret
  ever leaves your machine. https://0xshugo.gumroad.com/l/wbvgfb

Explanation is free. Execution across the whole surface, and the signed proof,
are the kit.

— Shugo

---

## Substack setup steps (admin — dispatch.aoifuture.com)

1. **Create the Security section** (piggyback + split, per the chosen strategy)
   - Dashboard → **Settings → Sections** → **New section** → name it `Security`.
   - Enable "let readers opt in by email" so culture-only subscribers aren't
     force-fed security posts and vice versa.
   - Publish future security posts (incl. "next free case") *into this section*.

2. **Set the welcome email** (delivers the tool link above)
   - Settings → **Emails → Welcome email to free subscribers → Edit**.
   - Paste Subject + Body above. Save.
   - Note: this welcome is **global** (all new free subscribers). That's fine —
     the tool link is a harmless bonus for culture subscribers and the exact
     payload security subscribers expect.

3. **Point the lead magnet at the Security section** — DONE (2026-07-04)
   - Security section web URL: `https://dispatch.aoifuture.com/s/security`
     (section id 418247). "Add new subscribers by default" is intentionally
     UNCHECKED so culture subscribers aren't force-added.
   - README and `landing/index.html` CTA links now point to `/s/security`.
   - Note: the `landing/index.html` inline capture iframe stays on the
     publication-wide `/embed` (works + captures email; the global welcome
     delivers the tool link and Security thread to everyone). Revisit if/when a
     confirmed section-scoped embed is needed.

4. **Upgrade path — drip/nurture sequence (if enabled on the account)**
   - Substack is rolling out drip sequences in 2026. If available, replace the
     single welcome with a 3-step Security sequence:
     welcome+tool → one concrete win (the constant-time / DoS fix) → the kit offer.
   - A sequence "replaces the standard welcome email," so only build it for the
     Security section if section-scoped sequences are supported; otherwise keep
     the global welcome above.

## Live destinations (verified 2026-07-04)

| Role | URL | Status |
|------|-----|--------|
| Tool (lead magnet) | github.com/AOI-Future/agent-webhook-check | PUBLIC |
| Book (1F, free/$9) | leanpub.com/agent-security | live, 100% |
| Kit (2F, $129/$399) | 0xshugo.gumroad.com/l/wbvgfb | published |
| List (capture) | dispatch.aoifuture.com | live (Substack) |
