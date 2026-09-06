/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#05070A',
        panel: '#0B0F14',
        panelalt: '#0F151C',
        text: '#E7ECF2',
        muted: '#8B96A3',
        border: '#1A222C',
        accent: '#3E8EFF',
        success: '#34D399',
        warning: '#FFB020',
        danger: '#FF2E4D',
        unknown: '#8291A3',
      },
      fontFamily: {
        display: ['Space Grotesk', 'sans-serif'],
        body: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'blink': 'blink 1s step-end infinite',
        'pulse-danger': 'pulse-danger 2.5s ease-in-out infinite',
        'float-slow': 'float-slow 20s ease-in-out infinite',
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        'pulse-danger': {
          '0%, 100%': { opacity: '0.15' },
          '50%': { opacity: '0.35' },
        },
        'float-slow': {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-12px)' },
        },
      },
    },
  },
  plugins: [],
};
