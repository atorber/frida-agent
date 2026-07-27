import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // 0.0.0.0，支持局域网 IP 访问
    port: 5173,
    proxy: {
      // 微信 Agent
      '/api': {
        target: 'http://127.0.0.1:19088',
        changeOrigin: true,
      },
      // 侧栏应用后端（助手/速记/工具）
      '/apps': {
        target: 'http://127.0.0.1:19089',
        changeOrigin: true,
      },
    },
  },
})
