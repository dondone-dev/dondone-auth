import { handleAdminApi } from '../../lib/admin-api'
import type { AuthEnv } from '../../lib/types'

export const onRequest: PagesFunction<AuthEnv> = async ({ request, env }) => {
  return handleAdminApi(request, env)
}
