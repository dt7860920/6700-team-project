/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // ONO palette — slate ground, indigo accent, semantic severities.
        ground: "#0b1020",
        panel: "#141a2e",
        edge: "#273150",
        ink: "#e8ecf8",
        muted: "#9aa6c6",
        accent: "#6366f1",
        sev: {
          low: "#3b82f6",
          medium: "#f59e0b",
          high: "#f97316",
          critical: "#ef4444",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "monospace"],
      },
    },
  },
  plugins: [],
};
