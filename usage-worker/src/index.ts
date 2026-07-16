import { UsageLedger } from './usage-ledger'

export { UsageLedger }

export default {
  async fetch(): Promise<Response> {
    return new Response('Not found', { status: 404 })
  },
}
