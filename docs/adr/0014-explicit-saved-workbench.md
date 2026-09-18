# ADR 0014: explicit saved workbench and local reopen

Status: accepted for the development checkpoint, 2026-09-18.

The desktop stores its navigator/inspector pane widths and the recent local
ELF path in the private local-project database, under a single settings row.
Schema v2 migrates v1 databases transactionally and preserves analyst facts.
The first-open schema transaction also serializes concurrent CLI/GUI starts.
Widths and paths are bounded and validated before save and after load.

Loading and saving run on the workbench worker thread, not the egui UI thread.
The UI waits for settings before constructing resizable panes, so persisted
widths are the first pane defaults. A visible **Save workbench layout** action
stores the current widths; **Reopen saved local ELF** performs a fresh import,
digest check, and local-project attach. Nothing is reopened automatically.

No remote credential, token-file path, binary content, selected function,
analysis artifact, or remote connection is saved. This is a small local
layout/recent-project feature, not general workspace/session restoration.
