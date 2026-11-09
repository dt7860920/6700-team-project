import { Composer } from "../components/Composer";
import type { InfoResponse, TargetSummary } from "../api/types";

interface Props {
  targets: TargetSummary[];
  selected: string | null;
  onSelect: (id: string) => void;
  snippet: string;
  onSnippet: (code: string) => void;
  onAnalyze: () => void;
  busy: boolean;
  info: InfoResponse | null;
  loadError: string | null;
}

export function NewScanPage({ loadError, ...composer }: Props) {
  return (
    <div className="flex min-h-full items-center justify-center px-4 py-10">
      <div className="w-full">
        {loadError && (
          <div className="mx-auto mb-5 max-w-2xl rounded-xl border border-sev-critical/40 bg-card p-4 text-sm text-sev-critical">
            {loadError}
          </div>
        )}
        <Composer {...composer} />
      </div>
    </div>
  );
}
