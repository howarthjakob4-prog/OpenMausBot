# OpenMausBot — Ferrum study notes

Study by Muse for Jakob Howarth (Ferrum), 2026-11-19. Source: this fork of
milind-soni/OpenMausBot, read from its README, DESIGN.md and docs/ — the app
itself was not run for this study. Added to the fork at Jakob's invitation.

## What it is

An open-source Grok Bot alternative: a chat app (TypeScript / React /
Electron, pnpm monorepo) where every bot in the sidebar is a real agent —
Claude Code, Codex, Grok, OpenCode or another ACP agent running locally —
with its own personality, its own model, its own computer and its own
connected apps. You talk to bots like contacts, watch them work, and approve
what matters. Local-first, bring-your-own-agent. It positions itself against
Grok Bot, Meta Muse, OpenAI dots and Cue by Manus.

## How it works — the moving parts

1. **Bots as contacts.** Each bot wraps a real engine process. The brain is
   picked per bot; keys are entered once and light everything up.
2. **The bot box (the "computer").** On their Cloud, every bot turn runs
   inside one unprivileged bubblewrap sandbox (`server/bot-box/`): the
   engine, its shell commands and its MCP servers live in the box; the
   server, its database and other bots' folders are not in it. The box gets
   the bot's own folder and the turn's working folder read-write, a private
   /tmp and PID namespace, loopback-only networking with two bridged ports,
   and a per-turn permission socket that approval questions travel through.
3. **Bot folders.** Each bot owns a folder (`workspaces/<bot>`) holding its
   standing instructions in `SOUL.md`, its skills (with every saved
   revision), its memory and its conversation folders.
4. **Approvals.** A per-bot approval level that maps onto the provider's own
   permission modes: Ask for approval / Auto-accept edits / Approve for me /
   Full Access. Full Access is the default for personal installs. The app
   only answers a request from an explicit grant, and a bot reading its own
   files (SOUL.md, skills, memory) never asks at any level.
5. **Decision model.** A fast, cheap model (TypeSafe Jev by default, or
   Cloudflare Workers AI, OpenRouter, or a custom endpoint) decides things
   like which bot answers in a room. It never does the work — the chosen bot
   still runs its own turn on its own engine.
6. **Teams.** A complete team can be installed from one Markdown file; bots
   and whole departments can be shared; a "Chief" bot can create teammates.
7. **Triggers and routines.** Schedules and webhooks can start bot turns;
   proactive routines exist as a first-class feature.
8. **Orchestration.** The whole thing can be driven over MCP, or headlessly
   from scripts and CI.

## What maps to Foundry

| OpenMausBot | Foundry (Ferrum) |
|---|---|
| Bots as contacts, one per seat | The five seats: Echo, Ember, Forge, Ledger, Anvil |
| Bot box / cloud desktop per bot | Ferrum Cloud computer |
| Approval levels per bot | VIP Approval cards (Paying always asks) |
| Per-bot memory + SOUL.md | Team memory; per-agent standing instructions |
| Triggers, schedules, routines | Routines and Watches |
| Decision model routing rooms | (No equivalent yet — open design question) |
| Team in one Markdown file | (No equivalent yet) |

## Ideas worth borrowing (ideas, not code)

- **Per-turn sandboxing:** run each agent turn in a throwaway box that can
  only see that bot's folder and that turn's work. Strong fit for Ferrum
  Cloud's locked-host design.
- **A cheap decision model for rooms:** when several bots share a chat, let
  a fast model pick who answers instead of waking every engine.
- **Own-files-never-ask:** approval rules that exempt a bot reading its own
  instructions, skills and memory — fewer nags, no safety loss.
- **Team-as-a-file:** a whole team defined in one Markdown file is a clean
  way to share or restore a team setup.

## License guardrails

- The main codebase is **Apache 2.0**: studying it and using its code are
  allowed, with attribution and the license terms kept.
- **`enterprise/` is NOT Apache 2.0.** It is source-available under the
  OpenMausBot Enterprise License: read/build/evaluate and dev/test use are
  fine; running it in production needs their license key, and hosting it for
  third parties or white-labelling needs a partner agreement. Do not copy
  `enterprise/` code into Ferrum products.

## Honest limits of this study

Written from the project's own documentation and file tree. Claims about
runtime behaviour (sandbox strength, answer quality, speed) are the
project's own and were not independently tested here.
