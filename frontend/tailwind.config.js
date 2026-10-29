/** Semantic palette: navy shell, teal = neutral interactive, amber = caution, red = phishing risk, green = healthy status only. */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { 950: "#080d18", 900: "#0b1220", 850: "#0f1729", 800: "#131c31", 700: "#1b2742", 600: "#26345a" },
        line: "#24304d",
        fog: { 100: "#e8edf6", 300: "#b4bfd3", 500: "#8493ad", 600: "#6b7a96" },
        teal: { 300: "#6fd9cd", 400: "#3cc4b5", 500: "#25a396", 600: "#1b8379" },
        amber: { 300: "#f1c46b", 400: "#e6a93b", 500: "#c98d22" },
        risk: { 300: "#f59a9a", 400: "#ef6b6b", 500: "#d94b4b", 900: "#3a1720" },
        periwinkle: "#8ea4d0",
        ok: { 400: "#4cc38a", 900: "#12301f" },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
