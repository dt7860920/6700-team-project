// Minimal unified-diff renderer: colorizes +/-/@@ lines. No dependency; the
// patch_diff is already a unified diff string from the API.

function lineClass(line: string): string {
  if (line.startsWith("+") && !line.startsWith("+++")) return "bg-ok/10 text-ok";
  if (line.startsWith("-") && !line.startsWith("---")) return "bg-sev-critical/10 text-sev-critical";
  if (line.startsWith("@@")) return "text-claydeep";
  if (line.startsWith("diff ") || line.startsWith("+++") || line.startsWith("---"))
    return "text-faint";
  return "text-body";
}

export function DiffView({ diff }: { diff: string }) {
  const lines = diff.replace(/\n$/, "").split("\n");
  return (
    <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-sand p-3 font-mono text-xs leading-relaxed">
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
