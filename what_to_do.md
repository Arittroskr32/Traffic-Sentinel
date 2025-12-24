
3) Small consistency nits (won’t crash, but worth cleaning)

In PCAP extraction you store header key user_agent (underscore) instead of typical user-agent. It won’t break detection since you scan header values + combined, but it’s slightly inconsistent with access/jsonl headers.

Your repo zip includes a .git/ directory, but your .dockerignore correctly excludes it from docker builds. (For sharing zips, excluding .git is still nicer.)

✅ Bottom line

Your codebase is structurally correct and functionally consistent with the project goal. The main problems are documentation mismatches, especially:

CLI commands

log ingestion defaults (access vs jsonl)

If you want, I can rewrite the README “Admin CLI” + “Log Mode Setup” sections so they exactly match your current implementation (no guessing, no broken commands).