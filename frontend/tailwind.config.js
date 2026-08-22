/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0d14',
          card: '#111726',
          border: '#1f293d',
          neon: '#00ffaa',
          cyan: '#00e5ff',
          blue: '#3b82f6',
          purple: '#a855f7',
          red: '#ff3366',
          yellow: '#ffcc00'
        }
      },
      boxShadow: {
        'neon': '0 0 15px rgba(0, 255, 170, 0.3)',
        'cyan-glow': '0 0 15px rgba(0, 229, 255, 0.3)',
        'cyber-card': '0 8px 32px 0 rgba(0, 0, 0, 0.37)'
      },
      fontFamily: {
        mono: ['Fira Code', 'JetBrains Mono', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif']
      }
    },
  },
  plugins: [],
}
