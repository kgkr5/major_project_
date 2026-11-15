import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Dark cybersecurity theme
        bg: {
          primary: '#0a0e1a',
          secondary: '#111827',
          tertiary: '#1a2332',
        },
        border: {
          DEFAULT: '#1f2937',
          accent: '#374151',
        },
        text: {
          primary: '#f9fafb',
          secondary: '#d1d5db',
          muted: '#6b7280',
        },
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#22c55e',
          normal: '#3b82f6',
        },
        accent: {
          cyan: '#06b6d4',
          blue: '#3b82f6',
          purple: '#8b5cf6',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config
