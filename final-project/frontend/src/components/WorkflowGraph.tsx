import { useMemo } from "react";
import {
  Background,
  BackgroundVariant,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { Scan, StageName } from "../api/types";
import { STAGE_LABELS, STAGE_ORDER } from "../lib/labels";

type NodeState = "pending" | "active" | "ok" | "skipped" | "failed";

interface NodeData extends Record<string, unknown> {
  label: string;
  kind: "stage" | "branch" | "satellite";
  sub?: string;
  state: NodeState;
}

// ---- live state derivation -------------------------------------------------

function stageStates(scan: Scan | null): Record<StageName, NodeState> {
  const out = {} as Record<StageName, NodeState>;
  const reported = new Set((scan?.pipeline ?? []).map((s) => s.stage));
  const firstPending = STAGE_ORDER.find((s) => !reported.has(s));
  for (const stage of STAGE_ORDER) {
    const done = scan?.pipeline.find((s) => s.stage === stage);
    if (done) out[stage] = done.status as NodeState;
    else if (scan?.status === "running" && stage === firstPending) out[stage] = "active";
    else out[stage] = "pending";
  }
  return out;
}

interface Derived {
  st: Record<StageName, NodeState>;
  usedRegex: boolean;
  noCandidates: boolean;
  verifyOk: boolean;
  verifyFailed: boolean;
  running: boolean;
  done: boolean;
}

function derive(scan: Scan | null): Derived {
  const st = stageStates(scan);
  const summaryOf = (s: StageName) =>
    (scan?.pipeline.find((p) => p.stage === s)?.summary ?? "").toLowerCase();
  const sastSummary = summaryOf("sast");
  const usedRegex = /regex|fallback/.test(sastSummary);
  const noCandidates =
    /\b0\b.*candidate|no candidate/.test(sastSummary) ||
    (st.sast === "ok" && (st.plan === "skipped" || st.analyze === "skipped"));
  const verify = scan?.pipeline.find((p) => p.stage === "verify");
  return {
    st,
    usedRegex,
    noCandidates,
    verifyOk: verify?.status === "ok",
    verifyFailed: verify?.status === "failed",
    running: scan?.status === "running" || scan?.status === "queued",
    done: scan?.status === "done",
  };
}

// ---- node rendering --------------------------------------------------------

const RING: Record<NodeState, string> = {
  pending: "border-border2 text-faint",
  active: "border-clay text-ink shadow-lift",
  ok: "border-ok/50 text-ink",
  skipped: "border-border2 text-faint opacity-70",
  failed: "border-sev-critical/60 text-ink",
};
const DOT: Record<NodeState, string> = {
  pending: "bg-border2",
  active: "bg-clay animate-pulse",
  ok: "bg-ok",
  skipped: "bg-faint/50",
  failed: "bg-sev-critical",
};

const H = "!h-1.5 !w-1.5 !min-w-0 !min-h-0 !border-0 !bg-border2 opacity-0";

function WorkflowNode({ data }: NodeProps) {
  const d = data as NodeData;
  const dashed = d.kind !== "stage";
  return (
    <div
      className={`flex w-[150px] flex-col gap-1 rounded-xl border bg-card px-3 py-2 shadow-card ${RING[d.state]} ${
        dashed ? "border-dashed" : ""
      } ${d.kind === "satellite" ? "bg-sand" : ""}`}
    >
      <Handle type="target" position={Position.Left} id="l" className={H} />
      <Handle type="target" position={Position.Top} id="tt" className={H} />
      <Handle type="target" position={Position.Bottom} id="bt" className={H} />
      <div className="flex items-center gap-1.5">
        <span className={`h-2 w-2 rounded-full ${DOT[d.state]}`} />
        <span className="text-[13px] font-semibold">{d.label}</span>
      </div>
      {d.sub && (
        <span className="line-clamp-2 font-mono text-xs leading-snug text-faint" title={d.sub}>
          {d.sub}
        </span>
      )}
      <Handle type="source" position={Position.Right} id="r" className={H} />
      <Handle type="source" position={Position.Top} id="t" className={H} />
      <Handle type="source" position={Position.Bottom} id="b" className={H} />
    </div>
  );
}

const nodeTypes = { wf: WorkflowNode };

// ---- colors ----------------------------------------------------------------

const C_OK = "#15803D";
const C_ACTIVE = "#D97757";
const C_IDLE = "#D6D2C8";
const C_FAINT = "#E8E5DC";
const C_FAIL = "#B23B2E";
const LABEL = { fill: "#6E6B64", fontFamily: "ui-monospace, monospace", fontSize: 12 } as const;
const LABEL_BG = { fill: "#FBFAF7" } as const;

export function WorkflowGraph({ scan }: { scan: Scan | null }) {
  const { nodes, edges } = useMemo(() => {
    const d = derive(scan);
    const sub = (s: StageName) => scan?.pipeline.find((p) => p.stage === s)?.summary;

    const mk = (
      id: string,
      label: string,
      kind: NodeData["kind"],
      x: number,
      y: number,
      state: NodeState,
      subtext?: string,
    ): Node => ({
      id,
      type: "wf",
      position: { x, y },
      data: { label, kind, state, sub: subtext },
      draggable: false,
      selectable: false,
    });

    const branchState = (taken: boolean, upstreamDone: boolean): NodeState =>
      !taken ? "pending" : upstreamDone ? "ok" : d.running ? "active" : "pending";

    const nodes: Node[] = [
      mk("ingest", STAGE_LABELS.ingest, "stage", 0, 120, d.st.ingest, sub("ingest")),
      mk("sast", STAGE_LABELS.sast, "stage", 210, 120, d.st.sast, sub("sast")),
      mk("regex", "Regex fallback", "branch", 410, 0, branchState(d.usedRegex, d.st.sast === "ok"), "SAST engine down"),
      mk("nocand", "No candidates", "branch", 410, 250, branchState(d.noCandidates, d.done), "nothing to analyze"),
      mk("plan", STAGE_LABELS.plan, "stage", 620, 120, d.st.plan, sub("plan")),
      mk("sandbox", "Jailed sandbox", "satellite", 790, -20, d.running ? "active" : "pending", "ephemeral · no egress"),
      mk("analyze", STAGE_LABELS.analyze, "stage", 840, 120, d.st.analyze, sub("analyze")),
      mk("model", "Qwen2.5-Coder", "satellite", 790, 250, d.running ? "active" : "pending", scan ? `backend: ${scan.model_backend}` : "frozen 7B"),
      mk("verify", STAGE_LABELS.verify, "stage", 1060, 120, d.st.verify, sub("verify")),
      mk("verified", "Verified", "branch", 1270, 40, branchState(d.verifyOk, d.verifyOk), "patch proven"),
      mk("unverified", "Unverified", "branch", 1270, 200, branchState(d.verifyFailed, d.verifyFailed), "model-asserted"),
    ];

    const stroke = (from: StageName): string =>
      d.st[from] === "ok" ? C_OK : d.st[from] === "active" ? C_ACTIVE : C_IDLE;
    const flowing = (from: StageName) => d.st[from] === "active" || (d.st[from] === "ok" && d.running);

    // Spine + conditional branches. `taken` branches use their live color; the
    // paths not taken stay faint so the actual route through the graph is clear.
    const edges: Edge[] = [
      spine("ingest", "sast", stroke("ingest"), flowing("ingest")),
      // sast outcomes (conditional)
      cond("sast-plan", "sast", "r", "plan", "l", "candidates", !d.noCandidates && !d.usedRegex, stroke("sast"), flowing("sast")),
      cond("sast-regex", "sast", "t", "regex", "l", "engine crash", d.usedRegex, d.usedRegex ? C_ACTIVE : C_FAINT, d.running && d.usedRegex),
      cond("regex-plan", "regex", "r", "plan", "tt", "", d.usedRegex, d.usedRegex ? stroke("sast") : C_FAINT, false),
      cond("sast-nocand", "sast", "b", "nocand", "l", "∅ none", d.noCandidates, d.noCandidates ? C_IDLE : C_FAINT, false),
      spine("plan", "analyze", stroke("plan"), flowing("plan")),
      spine("analyze", "verify", stroke("analyze"), flowing("analyze")),
      // verify outcomes (conditional)
      cond("verify-verified", "verify", "r", "verified", "l", "✓ proven", d.verifyOk, d.verifyOk ? C_OK : C_FAINT, false),
      cond("verify-unverified", "verify", "r", "unverified", "l", "✗ max", d.verifyFailed, d.verifyFailed ? C_FAIL : C_FAINT, false),
      // self-correct feedback loop (always shown as a possible edge)
      {
        id: "verify-analyze",
        source: "verify",
        sourceHandle: "b",
        target: "analyze",
        targetHandle: "bt",
        type: "smoothstep",
        label: "✗ self-correct",
        labelStyle: LABEL,
        labelBgStyle: LABEL_BG,
        style: { stroke: C_IDLE, strokeWidth: 1, strokeDasharray: "3 3" },
      },
      // context (model / sandbox)
      ctx("analyze-sandbox", "analyze", "t", "sandbox", "bt", "tools", d.running),
      ctx("plan-model", "plan", "b", "model", "tt", "infer", d.running),
      ctx("analyze-model", "analyze", "b", "model", "tt", "", d.running),
    ];

    return { nodes, edges };
  }, [scan]);

  return (
    <div className="card h-[380px] overflow-hidden p-0">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.22 }}
        minZoom={0.3}
        proOptions={{ hideAttribution: true }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        panOnDrag
        zoomOnScroll={false}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#E4E0D6" />
      </ReactFlow>
    </div>
  );
}

// ---- edge builders ---------------------------------------------------------

function spine(source: string, target: string, color: string, animated: boolean): Edge {
  return {
    id: `${source}-${target}`,
    source,
    sourceHandle: "r",
    target,
    targetHandle: "l",
    animated,
    style: { stroke: color, strokeWidth: 1.9 },
  };
}

function cond(
  id: string,
  source: string,
  sourceHandle: string,
  target: string,
  targetHandle: string,
  label: string,
  taken: boolean,
  color: string,
  animated: boolean,
): Edge {
  return {
    id,
    source,
    sourceHandle,
    target,
    targetHandle,
    animated,
    label: label || undefined,
    labelStyle: LABEL,
    labelBgStyle: LABEL_BG,
    type: "smoothstep",
    style: {
      stroke: color,
      strokeWidth: taken ? 1.8 : 1,
      strokeDasharray: taken ? undefined : "3 3",
    },
  };
}

function ctx(
  id: string,
  source: string,
  sourceHandle: string,
  target: string,
  targetHandle: string,
  label: string,
  animated: boolean,
): Edge {
  return {
    id,
    source,
    sourceHandle,
    target,
    targetHandle,
    animated,
    label: label || undefined,
    labelStyle: LABEL,
    labelBgStyle: LABEL_BG,
    type: "smoothstep",
    style: { stroke: C_IDLE, strokeWidth: 1, strokeDasharray: "4 4" },
  };
}
