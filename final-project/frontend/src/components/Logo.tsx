// ONO mark: a pointy-top hexagon (an agent-graph node / security badge) with a
// minus bar — "Negative One" (−1). Monoline, inherits color via currentColor.

export function Logo({ size = 24, className = "" }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      className={className}
      role="img"
      aria-label="Operation: Negative One"
    >
      <path
        d="M16 3 L27.26 9.5 V22.5 L16 29 L4.74 22.5 V9.5 Z"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <rect x="10.5" y="14.6" width="11" height="2.8" rx="1.4" fill="currentColor" />
      <circle cx="16" cy="3" r="2.1" fill="currentColor" />
    </svg>
  );
}
