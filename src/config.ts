// Public client configuration. Everything here is safe to commit — no secrets.
// Each value uses a committed default (so remote auto-deploy needs no dashboard
// step) that a build-time VITE_* env var can override, e.g. the Turnstile test
// key in local dev.

export const config = {
  // Dondone API base URL.
  apiBase:
    (import.meta.env.VITE_API_BASE as string | undefined) ||
    'https://api.dondone.dev',

  // Cloudflare Turnstile site key. Public by design (rendered into the served
  // page); the matching secret lives only in the Supabase dashboard.
  turnstileSiteKey:
    (import.meta.env.VITE_TURNSTILE_SITE_KEY as string | undefined) ||
    '0x4AAAAAAD6WmBBhTPOCE2qy',
} as const
