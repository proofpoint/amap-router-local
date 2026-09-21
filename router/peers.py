"""router/peers.py — the `peers` (a.k.a. `matrix`) review artifact.

Renders the derived cold-initiation matrix from `config.derive_matrix`
(the single derivation — enforcement stays `binding.check_cold`; this is
display-only and recomputed fresh every call, never stored). Nothing here
governs anything: it's a reviewability tool so an operator can see, at a
glance, who can cold-initiate to whom before wiring up a new instance.

Since the peer lane, the artifact renders BOTH declarations for a pair: the
mutual mail matrix as before, then the directed task graph
(`config.derive_peer_graph`, enforcement `binding.check_peer_edge`), so an
operator sees side by side what the loader already guarantees is disjoint.
`render_peers_json` emits only the graph, as `{recipient-address:
[sender-address, ...]}` — the shape the adapter renders `peers.json` from,
so the adapter's `--verify` can diff the two renderings of one fleet policy
element for element without transposing anything.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .config import (
    ALLOW_ANY, RouterConfig, address_for, derive_matrix, derive_peer_graph,
)

TRAILER = (
    "derived from per-instance peers at render time — never stored; governs "
    "COLD INITIATION ONLY (replies bind via the private ledger)"
)

ALLOW_ANY_LEGEND = (
    "* declares ALLOW_ANY; mutuality still required — ALLOW_ANY only relaxes "
    "the declaring side"
)


def cluster_order(cfg: RouterConfig, names: List[str]) -> List[str]:
    """`names`, reordered so instances that share a reachability set sit
    together — which turns the matrix from noise into visible blocks.

    Alphabetical order interleaves separate meshes and hides the structure that
    actually explains the topology. Grouping is by CLOSED neighbourhood
    (`peers | {self}`), which is identical for every member of a clique: in a
    12-member mesh each instance lists the other 11, so all twelve share the
    same closed set, while a bridge that also lists a second mesh does not. No
    knowledge of the policy's groups is needed, and none is available here — the
    router config stores expanded peers, not the `@group` references they came
    from.

    Clusters are ordered largest first, then by first member; members
    alphabetically. Deterministic, so two runs render identically.
    """
    sig = {n: frozenset(set(cfg.instances[n].peers) | {n}) for n in names}
    clusters: dict = {}
    for n in names:
        clusters.setdefault(sig[n], []).append(n)
    ordered = sorted(clusters.values(), key=lambda m: (-len(m), sorted(m)[0]))
    return [n for members in ordered for n in sorted(members)]


def cluster_index(cfg: RouterConfig, names: List[str]) -> List[int]:
    """Cluster number per name, in the order `names` is given. Used to band
    the rendering; adjacent equal numbers are one block."""
    sig = {n: frozenset(set(cfg.instances[n].peers) | {n}) for n in names}
    seen: dict = {}
    out = []
    for n in names:
        out.append(seen.setdefault(sig[n], len(seen)))
    return out


def cell_glyph(a: str, b: str, matrix) -> str:
    """`.` self, `y` may cold-initiate, `-` may not."""
    if a == b:
        return "."
    return "y" if matrix[a][b] else "-"


def _declared_lines(cfg: RouterConfig, names: List[str]) -> List[str]:
    width = max(len(n) for n in names) if names else 0
    lines = []
    for name in names:
        peers = cfg.instances[name].peers
        declared = ", ".join(sorted(peers)) if peers else "(none)"
        line = f"{name:<{width}}   peers: {declared}"
        if ALLOW_ANY in peers:
            line += (
                "  ** ANY — will accept cold-initiation from EVERY instance "
                "that also lists " + name + " **"
            )
        lines.append(line)
    return lines


def _matrix_lines(cfg: RouterConfig, names: List[str]) -> List[str]:
    """The n x n grid.

    Columns are NUMBERED rather than named, and the number is the row index, so
    the header stays one character wide per instance however long the names are.
    A 15-instance fleet of 30-character slugs is 450 columns of header
    otherwise, which wraps in any terminal and stops being a grid at all.

    Rows are cluster-ordered and blank-line separated per cluster, so a fleet of
    two meshes reads as two blocks with the bridges between them.
    """
    matrix = derive_matrix(cfg)
    allow_any_declarers = {n for n in names if ALLOW_ANY in cfg.instances[n].peers}

    def label(n: str) -> str:
        return n + ("*" if n in allow_any_declarers else "")

    idx_w = len(str(len(names)))
    row_label_width = max([len(label(n)) for n in names] + [0])
    pad = " " * (idx_w + 1 + row_label_width + 2)

    # Column ruler: the ones digit, with a tens row above it when it helps.
    lines = []
    if len(names) > 9:
        lines.append(pad + " ".join((str((i + 1) // 10) if (i + 1) >= 10 else " ")
                                    for i in range(len(names))))
    lines.append(pad + " ".join(str((i + 1) % 10) for i in range(len(names))))

    bands = cluster_index(cfg, names)
    for i, a in enumerate(names):
        if i and bands[i] != bands[i - 1]:
            lines.append("")
        cells = " ".join(cell_glyph(a, b, matrix) for b in names)
        lines.append(f"{i + 1:>{idx_w}} {label(a):<{row_label_width}}  {cells}")

    # Vacuously true with < 2 instances (the off-diagonal iteration is
    # empty) — gate explicitly so a single-instance config, which can
    # cold-initiate to nobody, never prints the banner.
    full_mesh = len(names) >= 2 and all(
        matrix[a][b] for a in names for b in names if a != b
    )
    if full_mesh:
        lines.append("")
        lines.append(
            "!! FULL MESH: every instance may cold-initiate to every other instance"
        )

    if allow_any_declarers:
        lines.append("")
        lines.append(ALLOW_ANY_LEGEND)

    return lines


PEER_GRAPH_HEADER = (
    "peer task graph — DIRECTED, declared on the receiver as peer_senders; "
    "governs the PEER LANE (results travel the reverse edge via the ledger)"
)


def _peer_graph_lines(cfg: RouterConfig) -> List[str]:
    """The directed task graph, one line per instance: `B  <- A, C` reads
    "A and C may task B". Rendered only when the fleet has a domain (no
    domain, no peer lane). Every instance is listed, including those nobody
    may task, so an absent edge is visible as `(none)` rather than as a
    missing row."""
    if not cfg.fleet_domain:
        return []
    graph = derive_peer_graph(cfg)
    names = sorted(graph)
    width = max(len(n) for n in names) if names else 0
    lines = [PEER_GRAPH_HEADER, f"fleet_domain: {cfg.fleet_domain}"]
    for name in names:
        senders = ", ".join(graph[name]) if graph[name] else "(none)"
        lines.append(f"{name:<{width}}   <- {senders}")
    return lines


def render_peers(cfg: RouterConfig) -> str:
    """Full peers review artifact: declared per-instance lists, then the
    n x n derived matrix, then the FULL MESH banner (if it applies) and the
    ALLOW_ANY legend (if any instance declares it), then — in a fleet with a
    domain — the directed peer task graph, then the governing-scope
    trailer. Column widths are computed from the longest instance name."""
    names = cluster_order(cfg, sorted(cfg.instances))
    lines: List[str] = []
    lines.extend(_declared_lines(cfg, names))
    lines.append("")
    lines.extend(_matrix_lines(cfg, names))
    graph_lines = _peer_graph_lines(cfg)
    if graph_lines:
        lines.append("")
        lines.extend(graph_lines)
    lines.append("")
    lines.append(TRAILER)
    return "\n".join(lines)


def peer_graph_addresses(cfg: RouterConfig) -> Dict[str, List[str]]:
    """`config.derive_peer_graph` with every name rendered through
    `address_for` — `{recipient-addr: [sender-addr, ...]}`, keys and lists
    sorted. Keyed by recipient, the shape the adapter's `--verify` diffs."""
    fd = cfg.fleet_domain
    return {
        address_for(recipient, fd): [address_for(s, fd) for s in senders]
        for recipient, senders in derive_peer_graph(cfg).items()
    }


def render_peers_json(cfg: RouterConfig) -> str:
    """`peers --json`: the directed task graph as addr-specs, and NOTHING
    else — no matrix, no banners — so the output is a document to diff, not
    a page to read. Deterministic (`sort_keys`, sorted lists)."""
    return json.dumps(peer_graph_addresses(cfg), indent=2, sort_keys=True)


# --- HTML -------------------------------------------------------------------
# A LOCAL FILE, deliberately. This renders a fleet's real instance names and
# reachability, which is deployment detail; it is written to a path the operator
# names and is never published anywhere. Self-contained for the same reason as
# the fleet console: no external stylesheet, no font, no script src, nothing
# that turns opening a review artifact into a network request.

_HTML_CSS = """
:root { --bg:#fbfbfd; --fg:#1b2430; --dim:#8a94a3; --line:#e2e6ec; --card:#fff;
        --yes:#1f7a4d; --yesbg:#e6f4ec; --no:#c2c8d0; --nobg:#f5f6f8;
        --self:#c9ced6; --accent:#12365c; --warn:#b03a3a; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#12151a; --fg:#e6e9ee; --dim:#8790a0; --line:#262c36; --card:#171b21;
          --yes:#5fd39b; --yesbg:#122a1f; --no:#3a424e; --nobg:#181c22;
          --self:#39414d; --accent:#7fb0e8; --warn:#e08585; } }
* { box-sizing:border-box } body { margin:0; background:var(--bg); color:var(--fg);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
.wrap { padding:28px 32px 56px; }
h1 { font-size:19px; margin:0 0 4px; color:var(--accent); }
.sub { color:var(--dim); font-size:12.5px; margin:0 0 22px; }
.banner { background:var(--yesbg); border-left:3px solid var(--yes); padding:9px 13px;
  margin:0 0 18px; font-size:13px; border-radius:0 4px 4px 0; }
.banner.warn { background:transparent; border-left-color:var(--warn); color:var(--warn); }
.scroll { overflow-x:auto; background:var(--card); border:1px solid var(--line);
  border-radius:7px; padding:14px; }
table { border-collapse:collapse; font-size:12px; }
th,td { padding:0; text-align:center; }
th.col { width:20px; color:var(--dim); font-weight:500; font-variant-numeric:tabular-nums;
  padding-bottom:5px; }
td.name { text-align:right; padding:0 11px 0 4px; white-space:nowrap;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:11.5px; }
td.num { color:var(--dim); text-align:right; padding-right:7px; font-variant-numeric:tabular-nums; }
td.c { width:20px; height:20px; font-family:ui-monospace,monospace; font-size:11px;
  border-radius:3px; }
td.y { color:var(--yes); background:var(--yesbg); font-weight:600; }
td.n { color:var(--no);  background:var(--nobg); }
td.s { color:var(--self); }
tr.bandtop td, tr.bandtop th { border-top:2px solid var(--line); }
tr:hover td.name, tr:hover td.num { color:var(--accent); font-weight:600; }
.legend { margin-top:20px; color:var(--dim); font-size:12px; max-width:62em; }
.legend b { color:var(--fg); font-weight:600; }
.legend code { background:var(--nobg); padding:1px 5px; border-radius:3px; }
"""


def render_peers_html(cfg: RouterConfig, source: str = "") -> str:
    """The same derivation as `render_peers`, as a self-contained page.

    The text grid stops being readable somewhere around a dozen instances with
    long slugs. This is the same data, ordered the same way, with the clusters
    banded so the block structure is visible without counting columns.
    """
    names = cluster_order(cfg, sorted(cfg.instances))
    matrix = derive_matrix(cfg)
    bands = cluster_index(cfg, names)
    allow_any = {n for n in names if ALLOW_ANY in cfg.instances[n].peers}
    n = len(names)

    def esc(t: str) -> str:
        return (t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    head = "".join(f'<th class="col">{i + 1}</th>' for i in range(n))
    rows = []
    for i, a in enumerate(names):
        top = " bandtop" if i and bands[i] != bands[i - 1] else ""
        cells = []
        for b in names:
            g = cell_glyph(a, b, matrix)
            cls = {"y": "y", "-": "n", ".": "s"}[g]
            cells.append(f'<td class="c {cls}">{g}</td>')
        star = "*" if a in allow_any else ""
        rows.append(f'<tr class="{top.strip()}"><td class="num">{i + 1}</td>'
                    f'<td class="name">{esc(a)}{star}</td>{"".join(cells)}</tr>')

    full_mesh = n >= 2 and all(matrix[a][b] for a in names for b in names if a != b)
    banners = []
    if full_mesh:
        banners.append('<div class="banner warn">FULL MESH — every instance may '
                       'cold-initiate to every other instance.</div>')
    if allow_any:
        banners.append(f'<div class="banner">{esc(ALLOW_ANY_LEGEND)}</div>')

    clusters = len(set(bands))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>peer matrix — {n} instances</title><style>{_HTML_CSS}</style></head><body>
<div class="wrap">
<h1>Cold-initiation matrix</h1>
<p class="sub">{n} instance(s), {clusters} cluster(s){' &middot; ' + esc(source) if source else ''}</p>
{''.join(banners)}
<div class="scroll"><table>
<thead><tr><th></th><th></th>{head}</tr></thead>
<tbody>{''.join(rows)}</tbody>
</table></div>
<div class="legend">
<p><code>y</code> row may cold-initiate to column &nbsp;
   <code>-</code> may not &nbsp; <code>.</code> self.
   Columns are numbered by row.</p>
<p><b>Rows are grouped by reachability</b>, not alphabetically — instances
   sharing a closed neighbourhood sit together, so a fleet of two meshes reads
   as blocks with the instances bridging them between. Horizontal rules mark
   the boundaries.</p>
<p><b>{esc(TRAILER)}</b></p>
</div></div></body></html>"""
