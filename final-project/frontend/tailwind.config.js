/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Team palette: floral-white "paper", navy ink, indigo accent, crimson for danger.
        paper: "#FFF8F0", // main workspace background (floral white)
        sand: "#F6ECDF", // sidebar / inset surfaces (deeper cream)
        card: "#FFFDF9", // raised cards
        border: "#EADFCF",
        border2: "#D9CBB6",
        ink: "#102542", // headings (navy)
        body: "#2A3852", // body text
        muted: "#58627A", // secondary text (AA on paper/sand)
        faint: "#5E6679", // metadata (AA on paper/sand)
        brand: "#2E3192", // brand accent (lighter indigo) - marks, hovers, live dots
        branddeep: "#1D1F68", // accent for text/buttons (indigo)
        brandsoft: "#ECEBF7", // tinted accent surface
        sev: {
          low: "#3B5F99",
          medium: "#94590A",
          high: "#B23C0A",
          critical: "#B3001B", // crimson
        },
        ok: "#15803D",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "sans-serif"],
        // Classic-terminal face for the scan timeline.
        terminal: ['"IBM Plex Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(16,37,66,0.04), 0 1px 3px rgba(16,37,66,0.06)",
        lift: "0 4px 14px -6px rgba(16,37,66,0.12)",
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
