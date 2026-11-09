import type { InfoResponse } from "../api/types";

export function Header({ info }: { info: InfoResponse | null }) {
  return (
    <header className="border-b border-edge">
      <div className="mx-auto flex max-w-3xl flex-wrap items-center justify-between gap-2 px-4 py-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-ink">
            Operation: Negative One
          </h1>
          <p className="text-xs text-muted">
            Scan an authorized codebase · prove the vulnerability · propose a verified fix
          </p>
        </div>
        {info && (
          <div className="flex items-center gap-2 text-xs text-muted">
            <span
              className="badge border-edge"
              title={`Model backend: ${info.model_backend}`}
            >
              {info.model_name}
            </span>
            <span className="badge border-edge">{info.environment}</span>
            <span className="text-muted/60">v{info.version}</span>
          </div>
        )}
      </div>
    </header>
  );
}
