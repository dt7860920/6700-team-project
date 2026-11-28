import type { ProgressEvent } from "../api/types";

function clock(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function ActivityLog({ events, live }: { events: ProgressEvent[]; live: boolean }) {
  if (events.length === 0) return null;
  // Newest first: new events appear at the top of the list.
  const newestFirst = [...events].reverse();
  return (
    <div className="card">
      <div className="mb-3 flex items-center gap-2">
        <span className="text-xs font-medium uppercase tracking-wide text-faint">Activity</span>
        {live && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-brand" />}
      </div>
      <ol className="space-y-1.5">
        {newestFirst.map((e, i) => {
          const last = i === 0;
          return (
            <li key={events.length - i} className="flex gap-3 text-sm">
              <span className="shrink-0 pt-px font-mono text-xs text-faint">{clock(e.at)}</span>
              <span className={`${last && live ? "text-ink" : "text-body"}`}>
                {last && live && <span className="mr-1 text-brand">›</span>}
                {e.message}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
