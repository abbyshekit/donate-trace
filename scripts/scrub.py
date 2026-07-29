#!/usr/bin/env python3
"""
scrub.py — deterministic anonymization pass for Trace Commons donations.

Removes the high-confidence, crisply-patterned leaks from a coding-agent
session before it is reviewed and donated:
  - home-directory paths and the username embedded in them
  - common secret formats (API keys, tokens, PEM blocks, JWTs, env assignments)
  - email addresses

This is intentionally NOT the whole anonymization story. Two layers back it up:
the skill performs an LLM/human review pass for fuzzy things a regex can't
recognize (personal names in prose, company names, internal codenames), and the
contributor reviews the exact diff before anything is uploaded. The split is
deliberate: code handles the patterns that have signatures, and a human handles
meaning.

What the server does and does not do, since this determines how much weight
this pass carries: the ingestion server re-runs its own deterministic redactor
over submitted envelopes (`rescrub_trace_envelope`), but it covers only event
content, structured payloads and the human-correction field, and it does NOT
run TruffleHog or any breadth scanner. Treat this script plus the local
scan.py run as the effective backstop, not as a first line before a stronger
server-side one. Run scan.py; do not skip it.

The script walks the parsed JSON of each session line and rewrites string
values in place, so it works regardless of where in the structure a string
sits. It writes a cleaned file plus a JSON report of every redaction.

Usage:
  python scrub.py --in session.jsonl --harness claude_code \
      --out cleaned.jsonl --report report.json
"""

import argparse
import json
import math
import re
from collections import Counter

# --- redaction patterns -----------------------------------------------------
# Order matters: more specific patterns run before more general ones.

HOME_PATH = re.compile(r'(\\?/(?:Users|home))\\?/([^/\\\s"\']+)')
# Dash-encoded home paths. Coding agents (e.g. Claude Code) name their project
# directories by replacing the slashes of an absolute path with dashes, so
# /Users/<name>/proj becomes the slug .claude/projects/-Users-<name>-proj. The
# slash-based HOME_PATH never sees these, so the username leaks. Anchored on the
# leading "/-Users-" / "/-home-" of the slug to avoid mangling hyphenated prose.
HOME_PATH_DASH = re.compile(r'(/-(?:Users|home))-([^-\s"\'\\/]+)')
# Windows user paths too
WIN_PATH = re.compile(r'([A-Za-z]:\\Users\\)([^\\\s"\']+)', re.IGNORECASE)

EMAIL = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')

# RFC1918 private / internal IPv4 addresses. Not a secret, but it leaks internal
# network topology (DB hosts, service IPs), so it is normalized like home paths
# rather than treated as rejectable secret material. The four-octet shape with a
# fixed private prefix avoids mangling version numbers like 1.2.3.4.
PRIVATE_IP = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|169\.254\.\d{1,3}\.\d{1,3})\b'
)

# Secrets — each tuple is (name, compiled regex). Keep these conservative
# enough to avoid mangling ordinary prose but broad enough to catch real keys.
SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("aws_secret", re.compile(r'\b(?i:aws_secret_access_key)\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?')),
    ("github_token", re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b')),
    ("hf_token", re.compile(r'\bhf_[A-Za-z0-9]{30,}\b')),
    ("openai_key", re.compile(r'\bsk-[A-Za-z0-9_\-]{20,}\b')),
    ("anthropic_key", re.compile(r'\bsk-ant-[A-Za-z0-9_\-]{20,}\b')),
    ("slack_token", re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,}\b')),
    ("google_api_key", re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
    ("jwt", re.compile(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b')),
    ("private_key_block", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----', re.DOTALL)),
    # Base64 tokens contain + and /, so the value class must include them or a
    # base64 bearer is only partially matched and the tail survives.
    ("bearer_token", re.compile(r'\b(?i:bearer)\s+[A-Za-z0-9+/_\-\.=]{20,}')),
    ("connection_string", re.compile(r'\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+')),
    # More vendor-prefixed tokens. A fixed prefix list can only catch shapes
    # someone thought to enumerate; the cue-gated entropy pass below is what
    # covers unknown-provider and ad hoc token shapes. Keep these
    # prefix-anchored to avoid false hits.
    ("github_fine_grained_pat", re.compile(r'\bgithub_pat_[0-9A-Za-z_]{22,}\b')),
    ("gitlab_pat", re.compile(r'\bglpat-[0-9A-Za-z_\-]{20,}\b')),
    ("gcp_oauth_token", re.compile(r'\bya29\.[0-9A-Za-z_\-]{20,}\b')),
    ("stripe_key", re.compile(r'\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b')),
    ("sendgrid_key", re.compile(r'\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b')),
    ("npm_token", re.compile(r'\bnpm_[0-9A-Za-z]{36}\b')),
    ("pypi_token", re.compile(r'\bpypi-[A-Za-z0-9_\-]{16,}\b')),
    # Twilio (SK + 32 hex) is deliberately NOT regexed here: the shape collides
    # with ordinary hashes/IDs and would cause false redactions. A cued Twilio
    # key is caught by the entropy pass below; an uncued one is left to the
    # local TruffleHog run in scan.py, whose validated detector knows the shape.
    ("azure_storage_key", re.compile(r'\bAccountKey=[A-Za-z0-9+/=]{40,}')),
    ("slack_webhook", re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+')),
    ("discord_webhook", re.compile(r'https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+')),
    # generic KEY=secret env assignments where the value looks secret-ish
    ("env_secret", re.compile(r'\b([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|API)[A-Z0-9_]*)\s*=\s*["\']?([^\s"\']{8,})["\']?')),
]


# --- contextual-entropy detection ------------------------------------------
# Ported from the ingestion server's deterministic redactor
# (trace-commons-protocol/src/trace_contribution.rs) so the skill and the
# server agree on what counts as opaque secret material. The vendor-prefix
# list above can only catch key shapes someone thought to enumerate; this
# catches unknown-provider and ad hoc tokens by shape instead.
#
# Cue-gating is mandatory, not a refinement. An ungated entropy scan over real
# transcripts flags on the order of 105k tokens (message ids, base64 content,
# UUIDs) against ~20 real secrets, which makes plain entropy scanning useless.
# A candidate is redacted only when a secret-shaped cue (api_key:, Bearer,
# password=, ...) appears within CUE_WINDOW chars before it.

# Chars scanned before a candidate for a secret cue. Wider than the server's 48
# because self-documenting field names are common in config and env dumps
# (`service_authentication_secret_config_value = <token>` pushes the cue well
# past 48 chars), and the window check is cheap.
CUE_WINDOW = 128
ENTROPY_MIN_LEN = 16
ENTROPY_BITS_MIN = 3.2

# Cue words, shared by the window check and the embedded-cue check below.
# A cue may be followed by the rest of a compound identifier before the
# separator (`service_authentication_secret_config_field = <token>`), but only
# across a _ or - boundary: without that restriction "token" also matches
# "tokenizer" and "tokens", and "secret" matches "secretName" -- all high
# frequency vocabulary in coding-agent traces, where the model name after
# "tokenizer:" is exactly the metadata this dataset exists to capture.
_CUE_WORDS = (
    r'authorization|bearer|api[_-]?keys?|secrets?|passwords?|passwd|pwd'
    r'|access[_-]?tokens?|client[_-]?secrets?|private[_-]?keys?|token|apikey'
    r'|credentials?|passphrase|mnemonic|seed[_-]phrase|cookie|dsn'
)
# ...but a tail naming a location or attribute rather than a value means the
# field holds a path, URL or label, not the credential itself
# (`authorization_url`, `private_key_path`, `api_key_name`).
_CUE_NOT_VALUE = (
    r'url|uri|path|file|filename|dir|name|id|type|kind|format|header|param'
    r'|field|env|var|prefix|suffix|length|len|count|expiry|expires|ttl|required'
)
_CUE_TAIL = r'(?:[_-](?!(?:' + _CUE_NOT_VALUE + r')\b)[\w-]*)?'

SECRET_CUE = re.compile(r'(?i)(' + _CUE_WORDS + r')' + _CUE_TAIL + r'["\'`:=\s]{1,6}$')

# An unspaced assignment such as api_key=<secret> is one token under the
# candidate class below (it contains _ and =), so the cue is swallowed into the
# candidate and never reaches the preceding window. Re-anchor past it.
EMBEDDED_CUE = re.compile(r'(?i)^(' + _CUE_WORDS + r')' + _CUE_TAIL + r'["\'`:=]{1,6}')

# Candidate runs. Deliberately unbounded ({1,} not {16,}): a run shorter than
# ENTROPY_MIN_LEN is not a candidate on its own, but it may be one FRAGMENT of a
# token split by a non-ASCII character (an en dash or smart quote pasted from a
# web page). Seeing every run lets _candidates rejoin those fragments before
# anything decides whether the whole is a secret; a {16,} pattern cannot, and
# leaks whichever fragment falls under the length bar.
CANDIDATE_RUN = re.compile(r'[A-Za-z0-9+/=_.\-]+')
# Only non-ASCII glue rejoins two runs. ASCII punctuation must NOT: `;` and `,`
# genuinely separate values, so gluing on them would chain redactions across
# ordinary text.
NON_ASCII_GLUE = re.compile(r'^[^\x00-\x7F]{1,3}$')


def token_shannon_entropy(s):
    """Shannon entropy in bits/char over the token's byte distribution."""
    if not s:
        return 0.0
    data = s.encode("utf-8", "replace")
    counts = Counter(data)
    length = len(data)
    total = 0.0
    for count in counts.values():
        p = count / length
        total -= p * math.log2(p)
    return total


def _candidates(content):
    """Yield (start, end, token) for each candidate, rejoining split tokens.

    Adjacent runs separated only by non-ASCII glue are emitted as one candidate,
    so a secret broken by a pasted en dash is judged, and redacted, whole.
    """
    pending = None  # [start, end]
    for run in CANDIDATE_RUN.finditer(content):
        if pending is not None:
            gap = content[pending[1]:run.start()]
            if NON_ASCII_GLUE.match(gap):
                pending[1] = run.end()
                continue
            yield pending[0], pending[1], content[pending[0]:pending[1]]
        pending = [run.start(), run.end()]
    if pending is not None:
        yield pending[0], pending[1], content[pending[0]:pending[1]]


def contextual_entropy_spans(content, force_cue=False):
    """Spans of high-entropy tokens that a secret cue points at.

    `force_cue` treats the whole string as already cued. It is set when the
    value arrived under a secret-named JSON key, where the cue lives in the key
    and never appears in the value's own text.

    Fail-closed by design: anything cued and high-entropy is redacted, with no
    structural-identifier exemption. A git SHA or message id essentially never
    sits behind an explicit `api_key:` label, whereas real secrets in exactly
    those shapes do (40- and 64-char hex HMAC/AES keys, tokens wearing an id
    prefix). Dropping a bit of signal costs nothing; publishing a key cannot be
    undone. Uncued candidates are never redacted, which is what keeps ordinary
    ids, hashes and base64 content intact.
    """
    spans = []
    for start, end, token in _candidates(content):
        # Unspaced assignment: strip the swallowed cue, keep the value only.
        embedded = EMBEDDED_CUE.match(token)
        cued = force_cue
        if embedded:
            start += embedded.end()
            token = token[embedded.end():]
            cued = True

        if len(token) < ENTROPY_MIN_LEN:
            continue

        # Gate order is chosen for cost, not logic: these conditions are
        # side-effect-free, so any order yields the same spans. The cue window
        # is both the cheapest check (bounded by CUE_WINDOW) and by far the most
        # selective, so it runs before the length-proportional entropy scan. A
        # single pasted base64 blob is one candidate, and entropy over it costs
        # milliseconds where the window check costs microseconds.
        if not cued:
            window = content[max(0, start - CUE_WINDOW):start]
            cued = bool(SECRET_CUE.search(window))
        if not cued:
            continue
        if token_shannon_entropy(token) < ENTROPY_BITS_MIN:
            continue
        spans.append((start, end))
    return spans

def key_is_secret_cue(key):
    """True when a JSON key name is itself a secret cue (`api_key`, `password`).

    Structured payloads put the cue in the key and the value in a sibling
    string, so the value never contains its own cue. Without this the most
    common real shape -- {"api_key": "<secret>"} in tool-call arguments --
    is invisible to the cue gate.
    """
    return isinstance(key, str) and bool(SECRET_CUE.search(key + ":"))


def _apply_contextual_entropy(s, counts, force_cue=False):
    """Redact cue-gated high-entropy tokens.

    Rebuilds the string in one forward pass. Replacing span by span would
    re-copy the whole string per span, which is quadratic on a long value
    holding many hits (a pasted credentials dump is the realistic case).
    """
    spans = contextual_entropy_spans(s, force_cue=force_cue)
    if not spans:
        return s
    pieces = []
    cursor = 0
    for start, end in spans:
        pieces.append(s[cursor:start])
        pieces.append("[REDACTED_SECRET]")
        counts["contextual_entropy"] += 1
        cursor = end
    pieces.append(s[cursor:])
    return "".join(pieces)


def redact_string(s, counts, force_cue=False):
    """Apply all redactions to a single string, tallying what was changed.

    `force_cue` marks the string as arriving under a secret-named JSON key,
    so the entropy pass treats it as cued without needing a cue in its text.
    """
    if not isinstance(s, str) or not s:
        return s

    # Secrets first (before paths/emails, since some secrets contain those shapes)
    for name, pat in SECRET_PATTERNS:
        def _sub(m, _name=name):
            counts[_name] += 1
            if _name == "env_secret":
                # keep the key name, redact the value
                return f"{m.group(1)}=[REDACTED_SECRET]"
            return "[REDACTED_SECRET]"
        s = pat.sub(_sub, s)

    # Cue-gated entropy pass. Runs after the fixed-format patterns so that a
    # token already replaced by a named detector is not counted twice, and
    # before paths/emails, which are redact-only rather than secret material.
    s = _apply_contextual_entropy(s, counts, force_cue=force_cue)

    # Home paths -> normalize the username segment
    def _home(m):
        counts["home_path"] += 1
        return f"{m.group(1)}/USER"
    s = HOME_PATH.sub(_home, s)

    def _home_dash(m):
        counts["home_path"] += 1
        return f"{m.group(1)}-USER"
    s = HOME_PATH_DASH.sub(_home_dash, s)

    def _win(m):
        counts["home_path"] += 1
        return f"{m.group(1)}USER"
    s = WIN_PATH.sub(_win, s)

    # Emails
    def _email(m):
        counts["email"] += 1
        return "[REDACTED_EMAIL]"
    s = EMAIL.sub(_email, s)

    # Private/internal IPs (redact-only, not treated as a rejectable secret)
    def _ip(m):
        counts["private_ip"] += 1
        return "[REDACTED_IP]"
    s = PRIVATE_IP.sub(_ip, s)

    return s


def walk(obj, counts, cued=False):
    """Recursively rewrite all string values in a parsed JSON structure.

    `cued` propagates down from a secret-named key, so everything beneath it
    inherits the cue: {"api_key": "<secret>"} is the usual shape in tool-call
    arguments, but {"api_keys": ["<secret>"]} and {"secrets": {"prod": ...}}
    are just as common, and the values never carry a cue of their own.
    """
    if isinstance(obj, str):
        return redact_string(obj, counts, force_cue=cued)
    if isinstance(obj, list):
        return [walk(x, counts, cued) for x in obj]
    if isinstance(obj, dict):
        # Keys can carry leaks too — some agents key objects by absolute file
        # path (e.g. {"/Users/<name>/proj/file": ...}), so scrub keys as well.
        out = {}
        for k, v in obj.items():
            cleaned_key = redact_string(k, counts) if isinstance(k, str) else k
            out[cleaned_key] = walk(v, counts, cued or key_is_secret_cue(k))
        return out
    return obj


def scrub_text(raw, harness):
    """Scrub a raw session string. Returns (cleaned_text, report_dict).

    Importable so the server can run the exact same detection as the skill,
    as a backstop. Mirrors the file-based main() below.
    """
    counts = Counter()
    lines_in = 0
    lines_out = []

    stripped = raw.strip()
    is_single_doc = stripped.startswith("{") and stripped.count("\n") > 0 and not _looks_like_jsonl(stripped)

    if is_single_doc:
        try:
            doc = json.loads(stripped)
            cleaned = walk(doc, counts)
            lines_out.append(json.dumps(cleaned, ensure_ascii=False))
            lines_in = 1
        except json.JSONDecodeError:
            is_single_doc = False

    if not is_single_doc:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            lines_in += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                lines_out.append(redact_string(line, counts))
                continue
            cleaned = walk(obj, counts)
            lines_out.append(json.dumps(cleaned, ensure_ascii=False))

    report = {
        "harness": harness,
        "lines_processed": lines_in,
        "redactions": dict(counts),
        "total_redactions": sum(counts.values()),
    }
    return "\n".join(lines_out) + "\n", report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--harness", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    with open(args.inp, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    cleaned_text, report = scrub_text(raw, args.harness)
    counts = Counter(report["redactions"])
    lines_in = report["lines_processed"]

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(cleaned_text)

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Human-readable summary to stdout for the skill to relay
    print(f"Scrubbed {lines_in} lines from {args.harness} session.")
    if counts:
        for k, v in counts.most_common():
            print(f"  {v}× {k}")
    else:
        print("  No high-confidence secrets or paths found by the automated pass.")
    print(f"\nCleaned file: {args.out}")
    print(f"Report: {args.report}")
    print("\nThis is the automated pass only. Now do the review pass for names,")
    print("company names, and internal references before showing the user.")


def _looks_like_jsonl(text):
    """Heuristic: if the first two non-empty lines each parse as JSON, it's JSONL."""
    parsed = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            json.loads(line)
            parsed += 1
        except json.JSONDecodeError:
            return False
        if parsed >= 2:
            return True
    return False


if __name__ == "__main__":
    main()
