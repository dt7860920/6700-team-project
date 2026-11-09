import type { ProgressEvent } from "../api/types";

function clock(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function ActivityLog({ events, live }: { events: ProgressEvent[]; live: boolean }) {
  if (events.length === 0) return null;
  // Most recent last; show newest at the bottom so the log reads like a transcript.
  return (
    <div className="card">
      <div className="mb-3 flex items-center gap-2">
        <span className="text-xs font-medium uppercase tracking-wide text-faint">Activity</span>
        {live && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-clay" />}
      </div>
      <ol className="space-y-1.5">
        {events.map((e, i) => {
          const last = i === events.length - 1;
          return (
            <li key={i} className="flex gap-3 text-sm">
              <span className="shrink-0 pt-px font-mono text-xs text-faint">{clock(e.at)}</span>
              <span className={`${last && live ? "text-ink" : "text-body"}`}>
                {last && live && <span className="mr-1 text-clay">›</span>}
                {e.message}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
