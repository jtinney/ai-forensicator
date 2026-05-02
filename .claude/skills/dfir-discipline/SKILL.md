# Skill: DFIR Discipline (shared rules across all phase agents)

<role>
Single source of truth for the rules every phase agent must follow. Each
agent's `<mandatory>` line points here.
</role>

<contents>
- [`DISCIPLINE.md`](./DISCIPLINE.md) — the rules. Defines:
  - `<audit-log-format>` — canonical row grammar
  - `<marker-self-attestation>` — `discipline_v4_loaded` requirement
  - `<index>` — concept → section map
  - Rules A, B, F, G, H, I, J, K, L, P-pcap, P-diskimage, P-priority, P-yara, P-sigma
- [`templates/survey-template.md`](./templates/survey-template.md) — Phase-2
  surveyor output skeleton; lint enforced by
  `.claude/skills/dfir-bootstrap/lint-survey.sh`.
- [`templates/INVENTORY.md`](./templates/INVENTORY.md) — full template map.
- Seven worked `reference/example-survey.md` files under each domain skill
  demonstrate the template populated for synthetic evidence.
</contents>

<usage>
Every phase agent's first action: read `DISCIPLINE.md`, then emit the marker
`discipline_v4_loaded` in the `result` field of its first audit row. The
orchestrator and `dfir-qa` grep for it.
</usage>
