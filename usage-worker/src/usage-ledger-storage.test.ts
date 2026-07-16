import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

describe('UsageLedger storage transactions', () => {
  it('uses the Durable Object transaction API instead of SQL transaction statements', () => {
    const source = readFileSync(
      fileURLToPath(new URL('./usage-ledger.ts', import.meta.url)),
      'utf8'
    )

    expect(source).toContain('transactionSync')
    expect(source).not.toMatch(/\.exec\(['"](?:BEGIN|COMMIT|ROLLBACK)/)
  })
})
