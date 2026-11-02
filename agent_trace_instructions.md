# Generalized Agent Trace Instructions

This base repository contains ten top-level problem folders named `PS01` through `PS10`. Before problem-specific work, the agent must ask the user to choose one PS and explicitly confirm the disclosed deletion scope; after confirmation, only that PS folder remains in the checkout. Submit the complete agent trace required by the **selected problem statement**. A trace helps evaluators understand the prompts, model responses, tool calls, and work performed during the session. Use the selected PS's authoritative statement to determine the exact trace artifact and submission requirements.

Include every agent session used for the selected PS, including sessions used to plan, code, debug, test, or review the solution. If multiple agent harnesses were used, include traces from each. Preserve original files and folder structure where practical; do not convert JSONL, SQLite, or other structured logs into screenshots or summaries. The cleanup of the other `PS##` folders applies only to the working repository; do not delete relevant agent trace records or session history stored outside those problem folders.

## 1. Determine the Trace Scope And Required Artifact

1. Use the selected folder name (`PS01`–`PS10`) as the problem ID, and read that folder's authoritative statement and submission instructions.
2. Check what that PS requires: trace format, filename, directory layout, whether a ZIP is mandatory, and where/how it must be submitted. Those challenge-specific requirements control if they differ from this guide.
3. Include sessions that materially contributed to the selected PS. If a session covered multiple PSs before cleanup, preserve its original trace and explain the association in a manifest; do not alter the original trace contents merely to split it.
4. Use `agent-trace/PS##/<harness-name>/` as the recommended staging layout when allowed. For a single-PS submission, `agent-trace/<harness-name>/` is also acceptable unless its specification requires another layout.
5. Include only relevant session files, not an entire home directory, application-data directory, or unrelated project history.

Recommended layout:

```text
agent-trace/
├── README.txt                 # Optional: problem IDs, harnesses, sessions, and any unavailable exports
└── PS03/
    ├── claude-code/
    └── codex/
```

Use the exact selected folder ID (`PS01` through `PS10`); do not invent IDs. If its challenge requires a specific ZIP structure or filename, follow that requirement. Otherwise, include the selected PS folder in the trace staging layout above.

## 2. Before Copying Or Sharing

1. Finish the sessions intended for submission, then quit the app or CLI before copying its files. This helps ensure logs are fully written.
2. Create a temporary staging folder named `agent-trace` somewhere easy to find. Use the selected PS folder ID and harness name in its subfolder layout, unless the selected challenge requires another layout.
3. Copy only the relevant traces for the selected PS. Preserve native JSONL, JSON, SQLite exports, subagent folders, and associated artifacts where practical. Do not confuse removal of unselected repository PS folders with permission to delete trace histories.
4. Review staged files before sharing. Traces can contain source code, local file paths, prompts, tool arguments and output, screenshots, and other private information. Remove or redact secrets (API keys, tokens, passwords, cookies, private keys), sensitive personal information, and material you are not permitted to share. Do not include authentication files, settings, or credentials.
5. Create the archive in the format and with the filename required by the active problem. If no format is specified, use `agent-trace.zip` containing the `agent-trace/` folder.
6. Open the resulting archive and verify that it contains the intended traces and no credentials or unrelated files. Submit it only through the official route specified for that problem.

Do not falsify, fabricate, or silently alter trace records. If redaction is necessary, preserve the original structure when possible and make clear that sensitive values were redacted. Follow challenge privacy and data-handling rules.

## 3. Claude Code

### Where traces are stored

Claude Code stores session transcripts by project under:

- **macOS/Linux:** `~/.claude/projects/`
- **Windows:** `%USERPROFILE%\.claude\projects\`

Each project folder contains session files, commonly JSONL files named with a session ID. Find the folder corresponding to the relevant repository checkout and copy only session files for the active problem into its staging folder, such as `agent-trace/problem_01/claude-code/`. Folder names may encode the project path; check session content and timestamps to identify the correct files.

### Export a readable transcript

In each relevant Claude Code session, run:

```text
/export
```

Save the exported transcript in the corresponding staging folder. `/export` produces a readable conversation export; include the original session JSONL files as well when available because they preserve the structured trace.

If Claude was used in the Claude web app or desktop chat rather than Claude Code, that is a different product history: use **Settings → Privacy → Export data** and follow the download instructions. Include only relevant conversation exports.

## 4. OpenAI Codex

### Where traces are stored

Codex CLI and local Codex app sessions commonly store structured rollout files under:

- **macOS/Linux:** `~/.codex/sessions/`
- **Windows:** `%USERPROFILE%\.codex\sessions\`

Files are organized into date folders and are typically named `rollout-*.jsonl`. If `CODEX_HOME` is set, look under `$CODEX_HOME/sessions/` instead. Copy only rollout JSONL files for sessions relevant to the active problem into its Codex staging folder. Use timestamps and session IDs to identify them. Include a matching `session_index.jsonl` only if useful for mapping session IDs to titles, and review it for unrelated information first.

Do **not** copy `auth.json`, `config.toml`, credential stores, or the whole `.codex` directory.

If Codex was used only in a hosted/cloud interface and there is no local rollout file, use the interface's conversation export or share/download option if available. If no transcript download is available, submit the conversation transcript in the format the interface provides and note in the manifest that it was a hosted session with no local trace file.

## 5. Google Antigravity

Antigravity writes a `transcript.jsonl` for each conversation under that conversation's `brain` folder. The transcript includes agent activity; the same folder can contain artifacts and screenshots associated with the conversation. Preserve the complete relevant conversation folder when its artifacts are needed to understand the trace.

Typical locations:

- **Antigravity app:** `~/.gemini/antigravity/brain/<conversation-id>/`
- **Antigravity CLI:** `~/.gemini/antigravity-cli/brain/<conversation-id>/`
- **Antigravity IDE:** `~/.gemini/antigravity-ide/brain/<conversation-id>/`
- **Windows:** look under `%USERPROFILE%\.gemini\antigravity\brain\`, `%USERPROFILE%\.gemini\antigravity-cli\brain\`, or `%USERPROFILE%\.gemini\antigravity-ide\brain\`, depending on the product used.

Within the relevant conversation folder, the transcript is at:

```text
.system_generated/logs/transcript.jsonl
```

Copy the complete relevant `<conversation-id>` folder(s) into the active problem's `antigravity/` staging folder. Do not copy the entire `.gemini` directory: it may contain unrelated data. Antigravity CLI's `last_conversations.json` is a session lookup cache, not the transcript itself.

## 6. OpenCode

OpenCode stores session and message data in a local SQLite database. Its default application-data directory is:

- **macOS/Linux:** `~/.local/share/opencode/`
- **Windows:** `%USERPROFILE%\.local\share\opencode\`

The database is usually `opencode.db`. To find its active path, including custom XDG or `OPENCODE_DB` locations, run:

```sh
opencode db path
```

Prefer exporting each relevant session as JSON rather than copying the database. List sessions and export each session for the active problem:

```sh
opencode session list --format json
opencode session export <session-id> > <session-id>.json
```

To redact sensitive transcript and file data during export, add `--sanitize`:

```sh
opencode session export <session-id> --sanitize > <session-id>.json
```

Place exported files in the active problem's `opencode/` staging folder. If the CLI is unavailable and the raw database is needed, quit OpenCode first, copy only `opencode.db` into staging, and inspect the copy for unrelated or private data. Never include `auth.json`, which can contain provider credentials. The default OpenCode data folder also contains logs and snapshots; those are not substitutes for session exports.

## 7. Other Harnesses

For any agent harness or coding tool not listed above (for example, Aider, Goose, RooCode, Cline, Devin, Factory, Cursor, Windsurf, GitHub Copilot, or JetBrains Junie):

1. **Finish and quit the session** so all logs and session files are completely written to disk.
2. **Create a tool subfolder** inside the active problem's trace folder named after the harness, for example `agent-trace/problem_01/cursor/` or `agent-trace/problem_01/windsurf/`.
3. **Export and copy the session traces for this problem:**
   - Use the tool's built-in session, chat, or trajectory export feature (UI or CLI) to save a readable or structured export in the harness folder.
   - Copy raw structured trace files for the relevant sessions from the tool's local storage directory (such as `.jsonl`, `.json`, `.db`, or chat history files), preserving original formats and any subagent folders. Include only sessions relevant to the active problem.
4. **Redact secrets and exclude credentials:** Remove or redact API keys, tokens, passwords, cookies, private keys, and sensitive personal information. Do **not** include authentication files, settings, or credential stores such as `auth.json`, `config.json`, `mcp.json`, `mcp_config.json`, or `.env`.
5. **Package and submit:** Follow §8 and the active problem's submission instructions.

If a harness provides no export or local trace file, include the best available transcript in the format it provides and describe the limitation in the optional `README.txt`. Do not claim a trace was included when it was not available.

## 8. Create The ZIP (When Required)

Use the filename and layout specified by the active problem. If it requires `agent-trace.zip`, or does not specify a filename but requires a ZIP, use the commands below from the directory containing `agent-trace/`.

### macOS or Linux

```sh
zip -r agent-trace.zip agent-trace
```

### Windows PowerShell

```powershell
Compress-Archive -Path .\agent-trace -DestinationPath .\agent-trace.zip -Force
```

Open the ZIP after creating it and confirm it contains only the intended problem-scoped traces and no credentials or unrelated files. Submit the archive with the active problem's other required artifacts. If the problem does not require a trace or ZIP, follow its stated instructions rather than assuming this artifact is mandatory.
