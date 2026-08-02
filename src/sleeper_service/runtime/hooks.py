"""Pre/post-hooks around every job (BUILD_PLAN § Job lifecycle, § Security).

Pre-hook: prompt-injection screening over all *untrusted* content — payload
prompt, file text, fetched link text. Heuristic pass in v1; a cheap-model
classifier can slot in behind the same function later. Default ON; a tenant
(settings.hooks.injection_screen) or agent (options.hooks.injection_screen)
can explicitly disable it.

Post-hooks: output schema validation (belt-and-braces over the runtime's own
structured output) and an opt-in PII redaction stub
(options.hooks.pii_redaction).
"""

import re

import jsonschema

INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    (name, re.compile(rx, re.IGNORECASE))
    for name, rx in [
        (
            "override_instructions",
            r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b.{0,40}\b(instruction|prompt|rule)",
        ),
        (
            "reveal_prompt",
            r"\b(reveal|show|print|repeat|output)\b.{0,40}\b(system|hidden|initial)\b.{0,20}\b(prompt|instruction|message)",
        ),
        (
            "role_reassignment",
            r"\byou are (now|no longer)\b|\bnew (persona|role|identity)\b|\bact as (?:an? )?(?:unrestricted|unfiltered|jailbroken)",
        ),
        (
            "privilege_claim",
            r"\b(as|i am) (your|the) (developer|administrator|creator|owner)\b.{0,40}\b(override|command|instruct)",
        ),
        ("delimiter_escape", r"<\/?(system|assistant)>|\[\/?(SYSTEM|INST)\]|```system"),
        (
            "tool_coercion",
            r"\b(always|never)\b.{0,30}\b(approve|deny|call|invoke)\b.{0,30}\btool\b",
        ),
    ]
]


def _tenant_rules(tenant_settings: dict) -> tuple[list[tuple[str, re.Pattern]], set[str]]:
    """Tenant-defined screening config (settings.hooks):
    - injection_patterns: [{"name": ..., "regex": ...}] — extra rules merged
      with the built-ins
    - injection_ignore_rules: ["tool_coercion", ...] — rule names suppressed
      for this tenant (e.g. a built-in that false-positives on their domain)
    Malformed entries are skipped here; the tenants API validates on write.
    """
    cfg = tenant_settings.get("hooks", {})
    extra: list[tuple[str, re.Pattern]] = []
    for item in cfg.get("injection_patterns", []):
        try:
            extra.append((str(item["name"]), re.compile(item["regex"], re.IGNORECASE)))
        except (KeyError, TypeError, re.error):
            continue
    ignore_rules = cfg.get("injection_ignore_rules", [])
    ignore = set(ignore_rules) if isinstance(ignore_rules, list) else set()
    return extra, ignore


def screen_injection(untrusted_texts: list[str], tenant_settings: dict | None = None) -> str | None:
    """Return the matched rule name if any untrusted text looks like an
    injection attempt, else None. Built-in heuristics plus the tenant's own
    patterns, minus the tenant's suppressed rules."""
    extra, ignore = _tenant_rules(tenant_settings or {})
    for text in untrusted_texts:
        for name, pattern in [*INJECTION_PATTERNS, *extra]:
            if name in ignore:
                continue
            if pattern.search(text):
                return name
    return None


def injection_screen_enabled(tenant_settings: dict, agent_options: dict) -> bool:
    return not (
        agent_options.get("hooks", {}).get("injection_screen") is False
        or tenant_settings.get("hooks", {}).get("injection_screen") is False
    )


def validate_hooks_settings(settings: dict) -> str | None:
    """Validate settings.hooks on tenant writes (friendly 422s; the runtime
    also skips malformed entries defensively)."""
    cfg = settings.get("hooks")
    if cfg is None:
        return None
    if not isinstance(cfg, dict):
        return "settings.hooks must be an object"
    patterns = cfg.get("injection_patterns", [])
    if not isinstance(patterns, list):
        return "hooks.injection_patterns must be a list of {name, regex}"
    for item in patterns:
        if not isinstance(item, dict) or not item.get("name") or "regex" not in item:
            return f"invalid injection pattern {item!r}: needs name and regex"
        try:
            re.compile(item["regex"])
        except (re.error, TypeError) as e:
            return f"invalid regex in pattern {item.get('name')!r}: {e}"
    ignore = cfg.get("injection_ignore_rules", [])
    if not isinstance(ignore, list) or not all(isinstance(r, str) for r in ignore):
        return "hooks.injection_ignore_rules must be a list of rule names"
    known = {name for name, _ in INJECTION_PATTERNS} | {
        p["name"] for p in patterns if isinstance(p, dict) and p.get("name")
    }
    unknown = set(ignore) - known
    if unknown:
        return f"unknown rule names in injection_ignore_rules: {sorted(unknown)}"
    return None


def validate_output_schema(output: dict, schema: dict) -> str | None:
    try:
        jsonschema.validate(output, schema)
        return None
    except jsonschema.ValidationError as e:
        return f"output failed schema validation: {e.message}"


PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")),
]


def redact_pii(value: object) -> tuple[object, int]:
    """Recursively redact PII-looking strings in a JSON-shaped structure."""
    count = 0
    if isinstance(value, str):
        for name, pattern in PII_PATTERNS:
            value, n = pattern.subn(f"[redacted:{name}]", value)
            count += n
        return value, count
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out[k], n = redact_pii(v)
            count += n
        return out, count
    if isinstance(value, list):
        items = []
        for v in value:
            item, n = redact_pii(v)
            items.append(item)
            count += n
        return items, count
    return value, count


def pii_redaction_enabled(agent_options: dict) -> bool:
    return agent_options.get("hooks", {}).get("pii_redaction") is True
