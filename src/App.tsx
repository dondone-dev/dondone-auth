import { useEffect, useState } from 'react'
import { supabase } from './supabase'
import './App.css'

function App() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [output, setOutput] = useState('')
  const [accessToken, setAccessToken] = useState<string | null>(null)

  async function refreshSession() {
    const { data, error } = await supabase.auth.getSession()

    if (error) {
      setOutput(JSON.stringify(error, null, 2))
      return
    }

    setAccessToken(data.session?.access_token ?? null)
    setOutput(JSON.stringify(data.session, null, 2))
  }

  useEffect(() => {
    refreshSession()

    const { data } = supabase.auth.onAuthStateChange((_event, session) => {
      setAccessToken(session?.access_token ?? null)
    })

    return () => {
      data.subscription.unsubscribe()
    }
  }, [])

  async function signUp() {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    })

    setOutput(JSON.stringify({ data, error }, null, 2))
  }

  async function signIn() {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    })

    setAccessToken(data.session?.access_token ?? null)
    setOutput(JSON.stringify({ data, error }, null, 2))
  }

  async function getUser() {
    const { data, error } = await supabase.auth.getUser()

    setOutput(JSON.stringify({ data, error }, null, 2))
  }

  async function signOut() {
    const { error } = await supabase.auth.signOut()

    setAccessToken(null)
    setOutput(JSON.stringify({ ok: !error, error }, null, 2))
  }

  return (
    <main style={{ maxWidth: 800, margin: '40px auto', padding: 20 }}>
      <h1>Supabase Auth Demo</h1>

      <div style={{ display: 'grid', gap: 12 }}>
        <input
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <input
          placeholder="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button onClick={signUp}>注册</button>
          <button onClick={signIn}>登录</button>
          <button onClick={getUser}>获取用户信息</button>
          <button onClick={refreshSession}>获取 Session / JWT</button>
          <button onClick={signOut}>退出</button>
        </div>
      </div>

      <h2>Access Token</h2>
      <textarea
        readOnly
        value={accessToken ?? ''}
        style={{ width: '100%', height: 120 }}
      />

      <h2>Output</h2>
      <pre style={{ whiteSpace: 'pre-wrap' }}>{output}</pre>
    </main>
  )
}

export default App
