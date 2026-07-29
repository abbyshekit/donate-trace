# Anonymization guide

Two passes. The scrubber (`scripts/scrub.py`) does pass one deterministically. You do pass two with judgment. Together they cover the field.

## Pass one — what the scrubber already handles
- Home-directory paths on Mac, Linux, and Windows → username replaced with `USER`
- Secret formats: AWS keys, GitHub/OpenAI/Anthropic/Slack/Google keys, JWTs, PEM private-key blocks, bearer tokens, database connection strings, and `KEY=value` env assignments where the key name implies a secret
- Unknown-provider and ad hoc tokens, via a cue-gated entropy pass: a high-entropy string is redacted when a secret cue (`api_key:`, `Bearer `, `password=`, `token=` …) appears just before it. Structural identifiers (UUIDs, `msg_`/`toolu_`/`req_` ids, git SHAs, content hashes) are allowlisted, so they survive.
- Email addresses and private/internal IPv4 addresses

You do not need to redo these. Trust the report it produces.

Note the limit of the cue gate: a secret with no cue near it (a bare token pasted on its own line, an unusual key name the cue list does not know) is invisible to pass one. That is a pass-two job, and it is why the local `scan.py` breadth scan is required rather than optional.

## Pass two — what you must check by reading
The scrubber recognizes patterns; it cannot recognize meaning. Read the cleaned session and look for:

- **Personal names** in prose — prompts, commit messages, code comments, review notes. Replace with `[NAME]`.
- **Bare usernames / handles**. The scrubber normalizes the username *inside paths* (`/Users/USER/`), but the same handle still appears on its own elsewhere: the owner column of `ls -l` output, `whoami`/`id` output, GitHub or Hugging Face URLs and account names (`github.com/<handle>`, `user: <handle>`), and prose. The scrubber cannot tell an arbitrary word is a username, so catch these by reading. Replace with `USER` (or `[NAME]` in prose).
- **Company / client / customer names**. Replace with `[COMPANY]`.
- **Internal hostnames and URLs** (`*.internal`, `*.local`, private IPs, intranet links). Replace with `[INTERNAL_URL]`.
- **Project codenames and ticket IDs** that identify a specific org (e.g. `JIRA-1234`, internal project names). Replace with `[REF]` if identifying.
- **Dates of birth and other identity-document details**. A DOB in prose (`born 2024-06-25`, `DOB 25/06/2024`, `turns 3 in June`) has no pattern the scrubber can safely key on, and combined with a name and a location it is a re-identification kit. Replace with `[DOB]`, or drop the sentence. The same applies to passport, SSN/NI, driver-licence and national-ID numbers if a session ever touched them.
- **Confidentiality and privilege markers, and the text they mark**. `attorney-client privileged`, `work product`, `subject to NDA`, `confidential — do not distribute`, `internal only`. Two reasons to stop when you see one. The marked material is by definition not yours to publish, and the marker itself signals the surrounding text is sensitive even where the specifics look mundane. Do not merely delete the marker and keep the body: remove both, or drop the session.
- **Anything else that could identify the author or their employer** — physical addresses, phone numbers the scrubber missed, unusual usernames in prose.

## Where to look per harness
- Claude Code: `message.content[].text`, Bash tool `input.command`, tool_result outputs
- Codex: `payload.content[].text`
- pi: `message.content` (string or block list)
- opencode: message/part text fields in the exported JSON
- Cursor: message/prompt text and shell-command/tool-call payloads in the `agent-transcripts/*.jsonl` lines

## The rule when unsure
Redact. The dataset is public and permanent. Dropping a bit of signal costs nothing; leaking a name or a key cannot be undone. If a whole session feels too sensitive to clean confidently, tell the user it may not be a good candidate to donate.

## What NOT to over-redact
Don't gut the session of its value. Library names, public API endpoints, common shell commands, framework names, error messages, and ordinary code are the point of the dataset. Keep them. The goal is to remove who and where, not what was done.
