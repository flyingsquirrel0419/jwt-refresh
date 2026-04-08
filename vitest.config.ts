import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['tests/**/*.test.ts'],
    coverage: {
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts', 'src/types.ts', 'src/stores/BaseStore.ts', 'src/testing/index.ts'],
      reporter: ['text', 'lcov'],
    },
  },
})
