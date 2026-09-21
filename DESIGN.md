# HydIR desktop design

HydIR is a dense analysis workbench. Its persistent navigator, central analysis
view, inspector, and optional console provide the primary structure. The
interface should make binary evidence and operation status easy to scan.

## Surfaces and layout

- Keep the dark canvas (`#15191c`) and flat panel surfaces (`#1d2226`) for
  workbench chrome and graph nodes. Use spacing, section headings, and thin
  dividers to group content within a pane.
- Do not use card layouts for metrics, pipeline stages, instruction rows,
  evidence fields, empty states, or patch summaries. Avoid nested boxes,
  rounded tiles, per-item borders, and decorative shadows.
- Graph nodes may have square outlines because their boundaries and edges
  convey control flow. Use a neutral fill and reserve colored outlines for
  selected, opaque, or external nodes.
- Keep analysis controls beside their relevant output. Preserve the existing
  resizable panes and scrolling for long machine data and generated code.

## Type and color

- Use clear heading size and weight to separate sections. Keep labels readable
  and use monospace for addresses, bytes, digests, and generated code.
- Use the existing neutral text (`#e1e5e3`) and secondary text (`#9da9aa`).
  Amber (`#e0aa5d`) identifies selection or a primary point of attention;
  green (`#7cbe98`) and red (`#e88b7c`) communicate operation status.
  Blue (`#68b1d8`) and violet (`#b491de`) distinguish analysis categories.
- Communicate status in text as well as color, including pending, blocked,
  available, and verified states. Do not turn every status into a colored tile.
