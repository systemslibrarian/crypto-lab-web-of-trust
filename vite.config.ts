import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-web-of-trust/',
  // Pin the preview port. Without this, `vite preview` binds its default 4173 —
  // a port a dozen labs in this fleet shared — so this lab could still squat on
  // a sibling's harness even after its own scripts moved off 4173. It also keeps
  // scripts/smoke.mjs honest: it tells you to reach it with `npm run preview`
  // and then connects to this port.
  preview: { port: 4710, strictPort: true },
});
