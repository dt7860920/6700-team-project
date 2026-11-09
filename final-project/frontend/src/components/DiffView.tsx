// Minimal unified-diff renderer: colorizes +/-/@@ lines. No dependency; the
// patch_diff is already a unified diff string from the API.

function lineClass(line: string): string {
  if (line.startsWith("+") && !line.startsWith("+++")) return "bg-emerald-500/10 text-emerald-200";
  if (line.startsWith("-") && !line.startsWith("---")) return "bg-rose-500/10 text-rose-200";
  if (line.startsWith("@@")) return "text-indigo-300";
  if (line.startsWith("diff ") || line.startsWith("+++") || line.startsWith("---"))
    return "text-muted";
  return "text-ink/80";
}

export function DiffView({ diff }: { diff: string }) {
  const lines = diff.replace(/\n$/, "").split("\n");
  return (
    <pre className="mt-2 overflow-x-auto rounded-lg border border-edge bg-ground p-3 font-mono text-xs leading-relaxed">
      <code>
        {lines.map((line, i) => (
          <div key={i} className={`${lineClass(line)} whitespace-pre px-1`}>
            {line || " "}
          </div>
        ))}
      </code>
    </pre>
  );
}
