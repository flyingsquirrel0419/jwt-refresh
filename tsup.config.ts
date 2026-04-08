import { defineConfig } from 'tsup'

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/stores/MemoryTokenStore.ts',
    'src/stores/RedisTokenStore.ts',
    'src/stores/PrismaTokenStore.ts',
    'src/stores/DrizzleTokenStore.ts',
    'src/integrations/express.ts',
    'src/integrations/fastify.ts',
    'src/integrations/nextjs.ts',
    'src/integrations/nestjs.ts',
    'src/testing/index.ts',
  ],
  clean: true,
  dts: true,
  format: ['esm', 'cjs'],
  sourcemap: true,
  target: 'node18',
  treeshake: true,
  splitting: false,
})
