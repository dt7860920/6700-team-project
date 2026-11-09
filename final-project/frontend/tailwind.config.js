/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Claude-style warm "paper" light theme with a clay/coral accent.
        paper: "#FBFAF7", // main workspace background
        sand: "#F3F1EA", // sidebar / inset surfaces
        card: "#FFFFFF", // raised cards
        border: "#E8E5DC",
        border2: "#DAD6CA",
        ink: "#20201D", // headings
        body: "#3C3A35", // body text
        muted: "#6E6B64", // secondary text (AA on paper/sand)
        faint: "#67645D", // metadata (AA on paper/sand)
        clay: "#D97757", // brand accent (the asterisk coral) — decorative only
        claydeep: "#A85330", // accent for text/buttons (AA on paper)
        claysoft: "#F6E9E2", // tinted accent surface
        sev: {
          low: "#2563EB",
          medium: "#A16207",
          high: "#C2410C",
          critical: "#B23B2E",
        },
        ok: "#15803D",
      },
      fontFamily: {
        serif: ['"Source Serif 4"', "Georgia", '"Times New Roman"', "serif"],
        sans: ['"Hanken Grotesk"', "ui-sans-serif", "system-ui", "-apple-system", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(32,32,29,0.04), 0 1px 3px rgba(32,32,29,0.06)",
        lift: "0 4px 14px -6px rgba(32,32,29,0.12)",
      },
      keyframes: {
        "fade-up": {
          from: { opacity: "0", transform: "translateY(6px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.35s ease-out both",
      },
    },
  },
  plugins: [],
};
