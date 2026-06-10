/**
 * 本地授权码流程端到端测试脚本
 * 需要 Node.js 18+（内置 fetch / crypto）
 *
 * 用法：node scripts/test-auth-flow.mjs
 */

import { createHash, randomBytes } from 'node:crypto'
import { createInterface } from 'node:readline'

// ── 配置（与 .dev.vars 里的 AUTH_APPS_JSON 保持一致） ──────────────────────
const BASE = 'http://localhost:8788'
const CLIENT_ID = 'myapp'
const REDIRECT_URI = 'http://localhost:3001/auth/callback'
// ───────────────────────────────────────────────────────────────────────────

function base64url(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

// 生成 PKCE 参数
const codeVerifier = base64url(randomBytes(32))
const codeChallenge = base64url(
  createHash('sha256').update(codeVerifier).digest()
)
const state = base64url(randomBytes(16))

// 构造授权入口 URL
const loginUrl = new URL(BASE + '/')
loginUrl.searchParams.set('client_id', CLIENT_ID)
loginUrl.searchParams.set('redirect_uri', REDIRECT_URI)
loginUrl.searchParams.set('state', state)
loginUrl.searchParams.set('code_challenge', codeChallenge)
loginUrl.searchParams.set('code_challenge_method', 'S256')

console.log('─'.repeat(60))
console.log('state:         ', state)
console.log('code_verifier: ', codeVerifier)
console.log('code_challenge:', codeChallenge)
console.log('─'.repeat(60))
console.log('\n① 在浏览器打开以下 URL 并完成登录：\n')
console.log(loginUrl.toString())
console.log()

const rl = createInterface({ input: process.stdin, output: process.stdout })

rl.question('② 登录后浏览器会跳转到回调地址（会报连接错误，属正常）。\n   粘贴完整的回调 URL（或只粘贴 code 值）：\n> ', async (input) => {
  rl.close()

  // 兼容粘贴完整 URL 或只有 code 值
  let code
  let returnedState

  try {
    const callbackUrl = new URL(input.trim())
    code = callbackUrl.searchParams.get('code')
    returnedState = callbackUrl.searchParams.get('state')
  } catch {
    code = input.trim()
  }

  if (!code) {
    console.error('\n❌ 未能解析出 code，请检查输入。')
    process.exit(1)
  }

  if (returnedState && returnedState !== state) {
    console.error(`\n❌ state 不匹配！期望 ${state}，收到 ${returnedState}`)
    process.exit(1)
  }

  if (returnedState) {
    console.log('\n✓ state 验证通过')
  }

  console.log('\n③ 正在兑换 code...\n')

  const res = await fetch(`${BASE}/api/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code,
      code_verifier: codeVerifier,
    }),
  })

  const body = await res.json()
  console.log(`状态码：${res.status}`)
  console.log(JSON.stringify(body, null, 2))

  if (!res.ok) {
    console.error('\n❌ 兑换失败。')
    process.exit(1)
  }

  console.log('\n✓ Token 兑换成功')

  // 验证 code 只能用一次
  console.log('\n④ 尝试重复使用同一 code（预期 410）...\n')

  const res2 = await fetch(`${BASE}/api/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code,
      code_verifier: codeVerifier,
    }),
  })

  const body2 = await res2.json()
  console.log(`状态码：${res2.status}`)
  console.log(JSON.stringify(body2, null, 2))

  if (res2.status === 410) {
    console.log('\n✓ code 重用被正确拒绝（410 code_expired）')
  } else {
    console.error('\n❌ code 重用应当返回 410，实际返回', res2.status)
  }

  // 验证 /api/me
  console.log('\n⑤ 验证 /api/me...\n')

  const res3 = await fetch(`${BASE}/api/me`, {
    headers: { Authorization: `Bearer ${body.access_token}` },
  })

  const body3 = await res3.json()
  console.log(`状态码：${res3.status}`)
  console.log(JSON.stringify(body3, null, 2))

  if (res3.ok) {
    console.log('\n✓ /api/me 返回用户信息')
  } else {
    console.error('\n❌ /api/me 请求失败')
  }

  console.log('\n' + '─'.repeat(60))
  console.log('全部测试完成。')
})
