import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#050816",
          panel: "#0b1020",
          card: "#111827",
          cyan: "#22d3ee",
          green: "#34d399",
          amber: "#f59e0b",
          red: "#fb7185",
        },
      },
      boxShadow: {
        glow: "0 0 40px rgba(34, 211, 238, 0.18)",
      },
      animation: {
        scan: "scan 3s ease-in-out infinite",
        float: "float 5s ease-in-out infinite",
      },
      keyframes: {
        scan: {
          "0%, 100%": { transform: "translateY(-20%)", opacity: "0.25" },
          "50%": { transform: "translateY(35%)", opacity: "0.8" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-10px)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
