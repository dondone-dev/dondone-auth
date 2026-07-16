import { DurableObject } from 'cloudflare:workers'
import {
  processAdjust,
  processConsume,
  processStatus,
  utcMidnightMs,
  validateClockSkew,
  validateLedgerAdjustmentRequest,
  validateLedgerRequest,
  validateLedgerStatusRequest,
  OPERATION_TTL_MS,
  type CounterStore,
  type OperationStore,
} from './usage-ledger-logic'

export class UsageLedger extends DurableObject<unknown> {
  private storage: DurableObjectStorage
  private sql: SqlStorage

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env)
    this.storage = ctx.storage
    this.sql = this.storage.sql
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
        create table if not exists counters (
          control_key text not null,
          window_start integer not null,
          used integer not null,
          updated_at integer not null,
          primary key (control_key, window_start)
        );
        create table if not exists operations (
          operation_id text primary key,
          request_hash text not null,
          response_json text not null,
          created_at integer not null,
          expires_at integer not null
        );
      `)
    })
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)
    if (request.method !== 'POST') return new Response('Not found', { status: 404 })

    switch (url.pathname) {
      case '/consume':
        return this.handleConsume(request)
      case '/status':
        return this.handleStatus(request)
      case '/adjust':
        return this.handleAdjust(request)
      default:
        return new Response('Not found', { status: 404 })
    }
  }

  private async handleConsume(request: Request): Promise<Response> {
    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonError('invalid_request', 400)
    }

    const parsed = validateLedgerRequest(body)
    if (!parsed) return jsonError('invalid_request', 400)

    const serverNow = Date.now()
    const skewError = validateClockSkew(parsed.now_ms, serverNow)
    if (skewError) return jsonError(skewError, 400)

    const result = this.storage.transactionSync(() =>
      processConsume(parsed, this.counterStore(), this.operationStore(), serverNow)
    )
    if ('conflict' in result) return jsonError('operation_conflict', 409)

    this.cleanup(serverNow, parsed.now_ms)
    return Response.json(result)
  }

  private async handleStatus(request: Request): Promise<Response> {
    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonError('invalid_request', 400)
    }

    const parsed = validateLedgerStatusRequest(body)
    if (!parsed) return jsonError('invalid_request', 400)

    const skewError = validateClockSkew(parsed.now_ms, Date.now())
    if (skewError) return jsonError(skewError, 400)

    const result = processStatus(parsed, this.counterStore())
    return Response.json(result)
  }

  private async handleAdjust(request: Request): Promise<Response> {
    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonError('invalid_request', 400)
    }

    const parsed = validateLedgerAdjustmentRequest(body)
    if (!parsed) return jsonError('invalid_request', 400)

    const serverNow = Date.now()
    const skewError = validateClockSkew(parsed.now_ms, serverNow)
    if (skewError) return jsonError(skewError, 400)

    const result = this.storage.transactionSync(() =>
      processAdjust(parsed, this.counterStore(), this.operationStore(), serverNow)
    )
    if ('conflict' in result) return jsonError('operation_conflict', 409)

    this.cleanup(serverNow, parsed.now_ms)
    return Response.json(result)
  }

  private counterStore(): CounterStore {
    return {
      getUsed: (controlKey, windowStart) => {
        const cursor = this.sql.exec(
          'select used from counters where control_key = ? and window_start = ?',
          controlKey,
          windowStart
        )
        for (const row of cursor) {
          return Number(row.used)
        }
        return 0
      },
      setUsed: (controlKey, windowStart, used, updatedAt) => {
        this.sql.exec(
          `insert into counters (control_key, window_start, used, updated_at)
           values (?, ?, ?, ?)
           on conflict(control_key, window_start) do update set
             used = excluded.used,
             updated_at = excluded.updated_at`,
          controlKey,
          windowStart,
          used,
          updatedAt
        )
      },
    }
  }

  private operationStore(): OperationStore {
    return {
      find: (operationId) => {
        const cursor = this.sql.exec(
          'select request_hash, response_json from operations where operation_id = ?',
          operationId
        )
        for (const row of cursor) {
          return {
            request_hash: String(row.request_hash),
            response_json: String(row.response_json),
          }
        }
        return null
      },
      insert: (operationId, requestHash, responseJson, createdAt, expiresAt) => {
        this.sql.exec(
          `insert into operations (operation_id, request_hash, response_json, created_at, expires_at)
           values (?, ?, ?, ?, ?)`,
          operationId,
          requestHash,
          responseJson,
          createdAt,
          expiresAt
        )
      },
    }
  }

  private cleanup(serverNowMs: number, nowMs: number): void {
    this.sql.exec('delete from operations where expires_at < ?', serverNowMs)

    const todayMidnight = utcMidnightMs(nowMs)
    this.sql.exec(
      'delete from counters where window_start > 0 and window_start < ?',
      todayMidnight
    )

    this.sql.exec(
      'delete from counters where window_start > 0 and updated_at < ?',
      serverNowMs - OPERATION_TTL_MS
    )
  }
}

function jsonError(error: string, status: number): Response {
  return Response.json({ error }, { status })
}
