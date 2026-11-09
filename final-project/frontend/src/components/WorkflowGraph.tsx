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

interface StageData extends Record<string, unknown> {
  label: string;
  kind: "stage" | "satellite";
  sub?: string;
  state: NodeState;
}

// Reuse the pipeline-merge logic: completed stages carry their real status; the
// first unreported stage while running is "active"; the rest are "pending".
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

const STATE_RING: Record<NodeState, string> = {
  pending: "border-border2 text-faint",
  active: "border-clay text-ink shadow-lift",
  ok: "border-ok/50 text-ink",
  skipped: "border-border2 text-faint",
  failed: "border-sev-critical/60 text-ink",
};
const STATE_DOT: Record<NodeState, string> = {
  pending: "bg-border2",
  active: "bg-clay animate-pulse",
  ok: "bg-ok",
  skipped: "bg-faint/60",
  failed: "bg-sev-critical",
};

function WorkflowNode({ data }: NodeProps) {
  const d = data as StageData;
  const satellite = d.kind === "satellite";
  return (
    <div
      className={`flex w-[150px] flex-col gap-1 rounded-xl border bg-card px-3 py-2 shadow-card ${STATE_RING[d.state]} ${
        satellite ? "border-dashed bg-sand" : ""
      }`}
    >
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-border2 !bg-paper" />
      <div className="flex items-center gap-1.5">
        <span className={`h-2 w-2 rounded-full ${STATE_DOT[d.state]}`} />
        <span className="text-[13px] font-semibold">{d.label}</span>
      </div>
      {d.sub && (
        <span className="line-clamp-2 font-mono text-[10px] leading-tight text-faint" title={d.sub}>
          {d.sub}
        </span>
      )}
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-border2 !bg-paper" />
    </div>
  );
}

const nodeTypes = { wf: WorkflowNode };

export function WorkflowGraph({ scan }: { scan: Scan | null }) {
  const { nodes, edges } = useMemo(() => {
    const st = stageStates(scan);
    const X = 190;
    const stageNode = (stage: StageName, i: number): Node => {
      const done = scan?.pipeline.find((s) => s.stage === stage);
      return {
        id: stage,
        type: "wf",
        position: { x: i * X, y: 90 },
        data: { label: STAGE_LABELS[stage], kind: "stage", state: st[stage], sub: done?.summary },
        draggable: false,
        selectable: false,
      };
    };
    const ns: Node[] = STAGE_ORDER.map(stageNode);
    ns.push(
      {
        id: "sandbox",
        type: "wf",
        position: { x: 1.5 * X, y: -30 },
        data: { label: "Jailed sandbox", kind: "satellite", sub: "ephemeral · no egress", state: "pending" },
        draggable: false,
        selectable: false,
      },
      {
        id: "model",
        type: "wf",
        position: { x: 2.5 * X, y: 210 },
        data: {
          label: "Qwen2.5-Coder",
          kind: "satellite",
          sub: scan?.model_backend ? `backend: ${scan.model_backend}` : "frozen 7B",
          state: scan?.status === "running" ? "active" : "pending",
        },
        draggable: false,
        selectable: false,
      },
    );

    const flowing = (from: StageName): boolean =>
      st[from] === "active" || (st[from] === "ok" && scan?.status === "running");
    const edgeStroke = (from: StageName): string =>
      st[from] === "ok" ? "#15803D" : flowing(from) ? "#D97757" : "#D6D2C8";
    const edge = (from: StageName, to: StageName): Edge => ({
      id: `${from}-${to}`,
      source: from,
      target: to,
      animated: flowing(from),
      style: { stroke: edgeStroke(from), strokeWidth: 1.75 },
    });
    const dashed = (id: string, source: string, target: string, label: string): Edge => ({
      id,
      source,
      target,
      animated: scan?.status === "running",
      label,
      labelStyle: { fill: "#6E6B64", fontFamily: "ui-monospace, monospace", fontSize: 9 },
      labelBgStyle: { fill: "#FBFAF7" },
      style: { stroke: "#D6D2C8", strokeWidth: 1, strokeDasharray: "4 4" },
    });

    const es: Edge[] = [
      edge("ingest", "sast"),
      edge("sast", "plan"),
      edge("plan", "analyze"),
      edge("analyze", "verify"),
      dashed("ingest-sandbox", "ingest", "sandbox", "clone"),
      dashed("analyze-sandbox", "analyze", "sandbox", "tools"),
      dashed("plan-model", "plan", "model", "infer"),
      dashed("analyze-model", "analyze", "model", "infer"),
      {
        id: "verify-analyze",
        source: "verify",
        target: "analyze",
        label: "self-correct",
        labelStyle: { fill: "#6E6B64", fontFamily: "ui-monospace, monospace", fontSize: 9 },
        labelBgStyle: { fill: "#FBFAF7" },
        style: { stroke: "#D6D2C8", strokeWidth: 1, strokeDasharray: "2 3" },
        type: "smoothstep",
      },
    ];
    return { nodes: ns, edges: es };
  }, [scan]);

  return (
    <div className="card h-[320px] overflow-hidden p-0">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.18 }}
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
