# Static Scanner Strategy — Prioritization Engine

## Your Logic (Validated)

> "The static scanner gives us the ability to prioritize on the weak points before we spend costly cycles with Claude or Bedrock to pinpoint the same flaws."

**Correct.** The static scanner should be the **prioritization engine** — cheap, fast, and high-signal. Improving it has high ROI because:

1. **Cost savings** — Fewer AI calls when we focus on high-risk files
2. **Better coverage** — Static catches patterns AI might miss (e.g., regex for `findByIdAndUpdate(req.body)`)
3. **Faster feedback** — Developers get instant results without API latency

---

## Current Gaps (Evidence: SecNotes)

| Gap | Impact | Example |
|-----|--------|---------|
| **Static findings not fed to prioritization** | AI picks files by name only; ignores which files have static hits | `app.js` had NoSQL injection but wasn't prioritized — AI had no signal |
| **Node.js/Express/Mongoose under-covered** | Modern stacks get few static hits | `findByIdAndUpdate(noteId, req.body)` — no rule |
| **rules_core.json MongoDB rule too narrow** | Only matches `db.collection($where)` | Mongoose uses `Model.findByIdAndUpdate(id, update)` — different API |
| **Prioritization prompt has no context** | AI sees file names + question only | No "app.js has 3 CRITICAL findings from static" |

---

## Improvement Roadmap

### Phase 1: Static → Prioritization (Highest ROI)

**Change:** Feed static findings into the prioritization prompt so the AI knows which files already have static hits.

**Before:** AI sees `["app.js", "index.html", ...]` + question  
**After:** AI sees `["app.js (3 static: req.body→DB, unvalidated)", "index.html (1 static: innerHTML)", ...]` + question

**Implementation:** Modify `PromptFactory.prioritization()` to accept optional `static_findings_by_file` and inject into the prompt. Orchestrator runs static first, then passes findings to prioritization.

**Cost impact:** Same prioritization API call; better file selection → fewer wasted deep-dive calls.

---

### Phase 2: Node.js / Mongoose Rules (rules_core.json)

Add patterns for modern stacks:

| Rule | Pattern | Severity |
|------|---------|----------|
| Mongoose findByIdAndUpdate with body | `findByIdAndUpdate\([^,]+,\s*req\.body` | CRITICAL |
| Mongoose findOneAndUpdate with body | `findOneAndUpdate\([^,]+,\s*req\.body` | CRITICAL |
| Express req.body to Model.update | `\.update\([^)]*req\.body` | CRITICAL |
| Express req.params to findOne | `findOne\(\s*\{\s*_id:\s*req\.params` | HIGH |
| Mongoose Model.create with body | `\.create\(req\.body` | HIGH (mass assignment) |

---

### Phase 3: Context-Aware Rules (Future)

**Idea:** Rules that require "source + sink" — e.g., `req.body` (source) flowing into `findByIdAndUpdate` (sink). Current scanner is line-based; this needs multi-line or AST analysis.

**Options:**
- Semgrep-style rules (source/sink)
- Two-pass: first find sinks, then check if nearby lines have unsanitized sources
- Defer to AI for taint analysis

---

### Phase 4: Tech-Stack-Aware Rule Loading

**Idea:** If `package.json` exists → load `rules_node.json`. If `requirements.txt` → load `rules_python.json`. Reduces noise (no PHP rules on Node projects) and allows framework-specific patterns.

### Phase 5: Future Rules

- LLM prompt injection (contextual; defer to AI analysis)
- Next.js Server Actions SSRF
- Narrow Axios/Go SSRF to reduce false positives

---

## Where to Begin

**Start with Phase 1** — it requires no new rules, no scanner changes, and immediately improves prioritization quality. The orchestrator already runs static first; we just need to pass those findings into the prioritization prompt.

**Then Phase 2** — add 5–10 high-value Node.js/Mongoose rules to `rules_core.json`. These will catch SecNotes-style flaws and similar patterns in other codebases.
