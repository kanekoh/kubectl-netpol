package visualizer

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"

	"github.com/kanekoh/kubectl-netpol/pkg/analyzer"
)

type htmlEdge struct {
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	SrcName string `json:"srcName"`
	DstName string `json:"dstName"`
	Label   string `json:"label"`
}

// RenderHTML writes a self-contained interactive HTML report.
//
// Design (intentionally not fighting Mermaid SVG edge labels):
//   - Diagram: Allow edges only, **no on-edge captions**
//   - Hover/pin node: dim unrelated nodes/lines; color remaining edges IN vs OUT
//   - Panel row hover: spotlight that one edge
//   - Port/layer details: HTML side panel driven by JSON
func RenderHTML(m *analyzer.Matrix, w io.Writer) {
	// Escape for HTML embedding so "<" in comments/labels cannot become real tags
	// inside <pre class="mermaid"> (browser parses unknown tags and breaks Mermaid).
	diagramBody := html.EscapeString(mermaidFlowchartBodyOpts(m, false))

	adj := make(map[string]map[string]bool)
	nodes := make(map[string]string)
	var edges []htmlEdge

	for _, g := range m.Groups {
		nodes[sanitizeID(g.Key())] = g.DisplayName()
	}

	for _, src := range m.Groups {
		if analyzer.IsNetworkZone(src) {
			continue
		}
		srcID := sanitizeID(src.Key())
		dstResults, ok := m.Results[src.Key()]
		if !ok {
			continue
		}
		for _, dst := range m.Groups {
			if src.Key() == dst.Key() {
				continue
			}
			pr, ok := dstResults[dst.Key()]
			if !ok || pr.Overall != analyzer.VerdictAllow {
				continue
			}
			if m.Synthesized && isDefaultLayer(pr) {
				continue
			}
			dstID := sanitizeID(dst.Key())
			edges = append(edges, htmlEdge{
				Src:     srcID,
				Dst:     dstID,
				SrcName: src.DisplayName(),
				DstName: dst.DisplayName(),
				Label:   edgeLabel(pr),
			})
			if adj[srcID] == nil {
				adj[srcID] = make(map[string]bool)
			}
			if adj[dstID] == nil {
				adj[dstID] = make(map[string]bool)
			}
			adj[srcID][dstID] = true
			adj[dstID][srcID] = true
		}
	}

	adjSlices := make(map[string][]string, len(adj))
	for nodeID, neighbors := range adj {
		ns := make([]string, 0, len(neighbors))
		for n := range neighbors {
			ns = append(ns, n)
		}
		sort.Strings(ns)
		adjSlices[nodeID] = ns
	}

	adjJSON, err := json.Marshal(adjSlices)
	if err != nil {
		adjJSON = []byte("{}")
	}
	edgesJSON, err := json.Marshal(edges)
	if err != nil {
		edgesJSON = []byte("[]")
	}
	nodesJSON, err := json.Marshal(nodes)
	if err != nil {
		nodesJSON = []byte("{}")
	}

	out := strings.Replace(htmlTemplate, "MERMAID_DIAGRAM_HERE", diagramBody, 1)
	out = strings.Replace(out, "ADJACENCY_JSON_HERE", string(adjJSON), 1)
	out = strings.Replace(out, "EDGES_JSON_HERE", string(edgesJSON), 1)
	out = strings.Replace(out, "NODES_JSON_HERE", string(nodesJSON), 1)
	fmt.Fprint(w, out)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Network Policy Connectivity</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>
    :root {
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #1e293b;
      --muted: #64748b;
      --border: #e2e8f0;
      --accent: #2563eb;
      --edge-out: #2563eb;   /* egress from focused node */
      --edge-in: #16a34a;    /* ingress into focused node */
      --edge-spotlight: #d97706;
    }
    * { box-sizing: border-box; }
    body {
      font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
      margin: 0;
      background: var(--bg);
      color: var(--text);
    }
    header { padding: 1.25rem 1.5rem 0.5rem; }
    header h1 { margin: 0 0 0.35rem; font-size: 1.35rem; }
    .legend { margin: 0; font-size: 0.9rem; color: var(--muted); }
    .swatch {
      display: inline-block;
      width: 0.7rem; height: 0.7rem;
      border-radius: 2px;
      vertical-align: -1px;
      margin: 0 0.15rem 0 0.55rem;
    }
    .swatch.out { background: var(--edge-out); }
    .swatch.in { background: var(--edge-in); }
    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 340px;
      gap: 1rem;
      padding: 1rem 1.5rem 1.5rem;
      align-items: start;
    }
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
    }
    #graph {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      overflow: auto;
      min-height: 360px;
      max-height: calc(100vh - 7rem);
      /* Keep native diagram size; scroll instead of squeeze (avoids node overlap). */
    }
    #graph .mermaid,
    #graph svg {
      max-width: none !important;
      width: auto !important;
      height: auto !important;
      min-width: max-content;
    }
    #panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      position: sticky;
      top: 1rem;
    }
    #panel h2 { margin: 0 0 0.5rem; font-size: 1rem; }
    #panel .hint {
      color: var(--muted);
      font-size: 0.85rem;
      margin: 0 0 0.75rem;
    }
    #focus-name {
      font-weight: 600;
      margin-bottom: 0.75rem;
      min-height: 1.25rem;
    }
    #conn-list { list-style: none; margin: 0; padding: 0; }
    #conn-list li {
      border-top: 1px solid var(--border);
      border-left: 3px solid transparent;
      padding: 0.55rem 0.5rem;
      font-size: 0.9rem;
      line-height: 1.35;
      cursor: pointer;
      border-radius: 0 4px 4px 0;
    }
    #conn-list li.dir-out { border-left-color: var(--edge-out); }
    #conn-list li.dir-in { border-left-color: var(--edge-in); }
    #conn-list li:hover,
    #conn-list li.active {
      background: #f1f5f9;
    }
    #conn-list .dir {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      font-weight: 600;
    }
    #conn-list li.dir-out .dir { color: var(--edge-out); }
    #conn-list li.dir-in .dir { color: var(--edge-in); }
    #conn-list .peer { font-weight: 500; }
    #conn-list .meta {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.8rem;
      color: var(--muted);
    }
    .node-dimmed { opacity: 0.14 !important; }
    path.edge-dimmed {
      opacity: 0.08 !important;
      stroke-opacity: 0.08 !important;
    }
    path.edge-out {
      stroke: var(--edge-out) !important;
      stroke-width: 2.75px !important;
      opacity: 1 !important;
      stroke-opacity: 1 !important;
    }
    path.edge-in {
      stroke: var(--edge-in) !important;
      stroke-width: 2.75px !important;
      opacity: 1 !important;
      stroke-opacity: 1 !important;
    }
    path.edge-spotlight {
      stroke: var(--edge-spotlight) !important;
      stroke-width: 4.5px !important;
      opacity: 1 !important;
      stroke-opacity: 1 !important;
    }
    .pinned-source > rect,
    .pinned-source > polygon {
      stroke: var(--accent) !important;
      stroke-width: 3px !important;
    }
  </style>
</head>
<body>
  <header>
    <h1>Network Policy Connectivity</h1>
    <p class="legend">
      Allow paths only. Hover a node to focus neighbors.
      <span class="swatch out"></span>OUT (egress)
      <span class="swatch in"></span>IN (ingress).
      Hover a panel row to spotlight that edge (amber). Click node to pin.
      Scroll inside the diagram if nodes look cramped.
    </p>
  </header>
  <div class="layout">
    <div id="graph">
      <pre class="mermaid">
MERMAID_DIAGRAM_HERE
      </pre>
    </div>
    <aside id="panel">
      <h2>Connections</h2>
      <p class="hint" id="panel-hint">Hover or click a workload node.</p>
      <div id="focus-name"></div>
      <ul id="conn-list"></ul>
    </aside>
  </div>

  <script>
    const adjacency = ADJACENCY_JSON_HERE;
    const edges = EDGES_JSON_HERE;
    const nodes = NODES_JSON_HERE;

    const nodeIds = new Set(Object.keys(nodes));
    edges.forEach(function(e) {
      nodeIds.add(e.src);
      nodeIds.add(e.dst);
    });

    let pinnedNode = null;
    let focusNode = null;
    let edgePaths = [];
    let nodeElems = null;
    // pathEl -> { src, dst } resolved once after render
    let pathMeta = [];

    // securityLevel 'loose' avoids iframe sandbox — required for file:// opens
    // (sandbox triggers: Unsafe attempt to load URL file:// ... unique security origins).
    mermaid.initialize({
      startOnLoad: false,
      theme: 'default',
      securityLevel: 'loose',
      maxTextSize: 100000,
      // useMaxWidth:false — do not shrink into a narrow pane (that causes overlap).
      flowchart: {
        htmlLabels: false,
        useMaxWidth: false,
        nodeSpacing: 60,
        rankSpacing: 100,
        padding: 24,
        wrappingWidth: 240
      }
    });

    mermaid.run({ nodes: document.querySelectorAll('.mermaid') }).then(function() {
      var svg = document.querySelector('#graph svg');
      if (svg) {
        svg.removeAttribute('width');
        svg.style.maxWidth = 'none';
        svg.style.width = 'auto';
        svg.style.height = 'auto';
      }
      setupHighlighting();
    }).catch(function(e) {
      var msg = (e && e.message) ? e.message : String(e);
      if (e && e.str) msg += ' | ' + e.str;
      console.error('Mermaid render error:', msg, e);
      var pre = document.querySelector('.mermaid');
      if (pre) {
        pre.textContent = 'Mermaid render failed: ' + msg +
          '\n\nTip: open via HTTP (python3 -m http.server) if using file:// still fails.';
      }
    });

    function extractNodeId(mermaidElemId) {
      const m = mermaidElemId.match(/^flowchart-(.+)-\d+$/);
      return m ? m[1] : mermaidElemId;
    }

    function collectEdgePaths(svg) {
      const group = svg.querySelector('.edgePaths');
      if (group) {
        const direct = Array.from(group.querySelectorAll(':scope > path'));
        if (direct.length) return direct;
        return Array.from(group.querySelectorAll('path'));
      }
      let paths = Array.from(svg.querySelectorAll('g.edgePath > path'));
      if (paths.length === 0) {
        paths = Array.from(svg.querySelectorAll('.edges path, path.flowchart-link'));
      }
      return paths;
    }

    function parseEndpoints(el) {
      if (!el) return null;
      const titleEl = el.querySelector ? el.querySelector('title') : null;
      const title = titleEl ? titleEl.textContent : '';
      if (title && title.indexOf('-->') >= 0) {
        const parts = title.split('-->');
        const src = (parts[0] || '').replace(/\s--[\s\S]*$/, '').trim();
        const dst = (parts[1] || '').trim();
        if (nodeIds.has(src) && nodeIds.has(dst)) return { src: src, dst: dst };
      }
      const id = el.id || '';
      const start = id.indexOf('L-');
      if (start < 0) return null;
      const body = id.slice(start + 2);
      const lastDash = body.lastIndexOf('-');
      if (lastDash <= 0 || !/^\d+$/.test(body.slice(lastDash + 1))) return null;
      const rest = body.slice(0, lastDash);
      const ids = Array.from(nodeIds).sort(function(a, b) { return b.length - a.length; });
      for (let i = 0; i < ids.length; i++) {
        const src = ids[i];
        const prefix = src + '-';
        if (rest.indexOf(prefix) === 0) {
          const dst = rest.slice(prefix.length);
          if (nodeIds.has(dst)) return { src: src, dst: dst };
        }
      }
      return null;
    }

    function buildPathMeta() {
      pathMeta = edgePaths.map(function(el, i) {
        return parseEndpoints(el) || (i < edges.length ? { src: edges[i].src, dst: edges[i].dst } : null);
      });
    }

    function findPathIndex(src, dst) {
      for (let i = 0; i < pathMeta.length; i++) {
        const m = pathMeta[i];
        if (m && m.src === src && m.dst === dst) return i;
      }
      return -1;
    }

    function clearEdgeClasses() {
      edgePaths.forEach(function(el) {
        el.classList.remove('edge-dimmed', 'edge-out', 'edge-in', 'edge-spotlight');
      });
    }

    function applyFocusColors(nodeId) {
      edgePaths.forEach(function(el, i) {
        const m = pathMeta[i];
        el.classList.remove('edge-dimmed', 'edge-out', 'edge-in', 'edge-spotlight');
        if (!m) {
          el.classList.add('edge-dimmed');
          return;
        }
        if (m.src === nodeId) {
          el.classList.add('edge-out');
        } else if (m.dst === nodeId) {
          el.classList.add('edge-in');
        } else {
          el.classList.add('edge-dimmed');
        }
      });
    }

    function spotlightEdge(src, dst, dir) {
      // Keep IN/OUT coloring for other focus edges; amber the selected one.
      if (focusNode) {
        applyFocusColors(focusNode);
      } else {
        clearEdgeClasses();
      }
      const idx = findPathIndex(src, dst);
      if (idx < 0) return;
      const el = edgePaths[idx];
      el.classList.remove('edge-dimmed', 'edge-out', 'edge-in');
      el.classList.add('edge-spotlight');
      // Preserve a hint of direction via CSS variable override
      if (dir === 'out') {
        el.style.stroke = getComputedStyle(document.documentElement).getPropertyValue('--edge-out').trim();
      } else if (dir === 'in') {
        el.style.stroke = getComputedStyle(document.documentElement).getPropertyValue('--edge-in').trim();
      }
      el.style.strokeWidth = '4.5px';
    }

    function clearSpotlightStyle() {
      edgePaths.forEach(function(el) {
        el.style.stroke = '';
        el.style.strokeWidth = '';
      });
      if (focusNode) {
        applyFocusColors(focusNode);
      } else {
        clearEdgeClasses();
      }
    }

    function showPanel(nodeId) {
      const nameEl = document.getElementById('focus-name');
      const listEl = document.getElementById('conn-list');
      const hintEl = document.getElementById('panel-hint');
      nameEl.textContent = nodes[nodeId] || nodeId;
      hintEl.textContent = 'Hover a row to color that edge. OUT=blue, IN=green.';
      listEl.innerHTML = '';

      const related = edges.filter(function(e) {
        return e.src === nodeId || e.dst === nodeId;
      });
      if (related.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No Allow edges.';
        listEl.appendChild(li);
        return;
      }

      related.forEach(function(e) {
        const outbound = e.src === nodeId;
        const li = document.createElement('li');
        li.className = outbound ? 'dir-out' : 'dir-in';
        li.dataset.src = e.src;
        li.dataset.dst = e.dst;
        li.dataset.dir = outbound ? 'out' : 'in';

        const dir = document.createElement('div');
        dir.className = 'dir';
        dir.textContent = outbound ? 'OUT →' : '← IN';
        const peer = document.createElement('div');
        peer.className = 'peer';
        peer.textContent = outbound ? e.dstName : e.srcName;
        const meta = document.createElement('div');
        meta.className = 'meta';
        meta.textContent = e.label;

        li.appendChild(dir);
        li.appendChild(peer);
        li.appendChild(meta);

        li.addEventListener('mouseenter', function() {
          li.classList.add('active');
          spotlightEdge(e.src, e.dst, outbound ? 'out' : 'in');
        });
        li.addEventListener('mouseleave', function() {
          li.classList.remove('active');
          clearSpotlightStyle();
        });

        listEl.appendChild(li);
      });
    }

    function clearPanel() {
      document.getElementById('focus-name').textContent = '';
      document.getElementById('panel-hint').textContent = 'Hover or click a workload node.';
      document.getElementById('conn-list').innerHTML = '';
    }

    function highlightNode(nodeId) {
      focusNode = nodeId;
      const neighbors = new Set(adjacency[nodeId] || []);
      nodeElems.forEach(function(el) {
        const id = extractNodeId(el.id || '');
        el.classList.toggle('node-dimmed', !(id === nodeId || neighbors.has(id)));
      });
      applyFocusColors(nodeId);
      showPanel(nodeId);
    }

    function clearHighlight() {
      focusNode = null;
      nodeElems.forEach(function(el) { el.classList.remove('node-dimmed'); });
      clearEdgeClasses();
      edgePaths.forEach(function(el) {
        el.style.stroke = '';
        el.style.strokeWidth = '';
      });
      clearPanel();
    }

    function setupHighlighting() {
      const svg = document.querySelector('#graph svg');
      if (!svg) return;

      nodeElems = svg.querySelectorAll('g.node');
      edgePaths = collectEdgePaths(svg);
      buildPathMeta();

      nodeElems.forEach(function(nodeEl) {
        const nodeId = extractNodeId(nodeEl.id || '');
        nodeEl.style.cursor = 'pointer';

        nodeEl.addEventListener('mouseenter', function() {
          if (pinnedNode) return;
          highlightNode(nodeId);
        });

        nodeEl.addEventListener('mouseleave', function(e) {
          if (pinnedNode) return;
          // Allow moving into the side panel without clearing focus.
          const to = e.relatedTarget;
          if (to && document.getElementById('panel').contains(to)) return;
          if (to && document.getElementById('graph').contains(to)) return;
          clearHighlight();
        });

        nodeEl.addEventListener('click', function(e) {
          e.stopPropagation();
          if (pinnedNode === nodeId) {
            pinnedNode = null;
            nodeEl.classList.remove('pinned-source');
            clearHighlight();
          } else {
            nodeElems.forEach(function(n) { n.classList.remove('pinned-source'); });
            pinnedNode = nodeId;
            nodeEl.classList.add('pinned-source');
            highlightNode(nodeId);
          }
        });
      });

      svg.addEventListener('click', function() {
        if (pinnedNode) {
          pinnedNode = null;
          nodeElems.forEach(function(n) { n.classList.remove('pinned-source'); });
          clearHighlight();
        }
      });

      const panel = document.getElementById('panel');
      panel.addEventListener('mouseleave', function(e) {
        clearSpotlightStyle();
        if (pinnedNode) return;
        const to = e.relatedTarget;
        if (to && document.getElementById('graph').contains(to)) return;
        clearHighlight();
      });
    }
  </script>
</body>
</html>
`
