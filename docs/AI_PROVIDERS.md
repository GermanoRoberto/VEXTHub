# AI Providers

VextHub supports optional AI enrichment for defensive endpoint telemetry triage. The local detector still creates alerts and remains the source of truth. AI output is used as a senior analyst runbook for summaries, prioritization, investigation, containment, remediation, verification, prevention, and escalation guidance.

The provider profile pattern follows the useful part of OpenClaude's approach: choose a provider, model, base URL, and API key through environment variables. VextHub does not import OpenClaude's CLI, shell execution, proxying, or tool-running behavior.

## Gemini

```env
VEXTHUB_AI_ENABLED=true
VEXTHUB_AI_PROVIDER=gemini
VEXTHUB_AI_MODEL=gemini-2.0-flash
GEMINI_API_KEY=your-key
```

Optional overrides:

```env
VEXTHUB_GEMINI_API_KEY=your-key
VEXTHUB_AI_BASE_URL=https://generativelanguage.googleapis.com/v1beta
```

Gemini uses `models.generateContent` and asks for `application/json` output.

## Groq

```env
VEXTHUB_AI_ENABLED=true
VEXTHUB_AI_PROVIDER=groq
VEXTHUB_AI_MODEL=llama-3.3-70b-versatile
GROQ_API_KEY=your-key
```

Optional overrides:

```env
VEXTHUB_GROQ_API_KEY=your-key
VEXTHUB_AI_BASE_URL=https://api.groq.com/openai/v1
```

Groq uses the OpenAI-compatible `chat/completions` endpoint with JSON mode.

## Custom OpenCloud-Compatible Endpoint

Keep this mode for an internal or private defensive triage service.

```env
VEXTHUB_AI_ENABLED=true
VEXTHUB_AI_PROVIDER=opencloud-compatible
VEXTHUB_AI_ENDPOINT=https://ai-gateway.example.com/triage
VEXTHUB_AI_API_KEY=your-key
VEXTHUB_AI_MODEL=optional-model-id
```

## Safety Boundaries

- Provider URLs must use HTTPS, except `localhost`, `127.0.0.1`, or `::1` during development.
- The payload is capped to the top telemetry findings and evidence is truncated before it leaves VextHub.
- The prompt forbids exploit steps, credential collection, persistence, evasion, bypass, and destructive guidance.
- AI responses must normalize to JSON keys `summary`, `confidence`, `risk_level`, `analyst_assessment`, `recommended_next_steps`, `investigation_steps`, `containment_steps`, `remediation_steps`, `verification_steps`, and `prevention_steps`.
- The analyst prompt requires uncertainty handling: when telemetry is incomplete, the AI must list evidence gaps and lower confidence instead of inventing context.
- The AI must not recommend arbitrary shell execution through the agent. VextHub agent actions remain limited to refresh inventory, compliance scan, and agent update.
- Governance context is injected from `src/data/governance-frameworks.json` as a curated summary inspired by the public frameworks guide. AI responses may map telemetry to frameworks, controls, audit evidence, and management actions, but must not claim certification or compliance without supplied evidence.
- Never store provider API keys in source control. Use a managed secret store in production.
