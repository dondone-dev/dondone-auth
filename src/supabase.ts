import { createClient } from '@supabase/supabase-js'

export const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
  {
    auth: {
      // PKCE puts the OAuth callback in ?code= (query), which survives Cloudflare
      // bot/challenge redirects. Implicit flow uses #access_token= (hash), which
      // the browser never sends to the server and is lost after a CF interstitial.
      flowType: 'pkce',
      experimental: { passkey: true },
    },
  }
)
