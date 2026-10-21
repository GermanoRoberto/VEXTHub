import { type NextRequest } from 'next/server'
import { updateSession } from '@/utils/supabase/middleware'

export default async function proxy(request: NextRequest) {
  return await updateSession(request)
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - telemetry endpoints that use agent authentication instead of dashboard cookies
     * Feel free to modify this pattern to include more paths.
     */
    '/((?!_next/static|_next/image|favicon.ico|api/dev(?:/.*)?|dev(?:/.*)?|api/telemetry(?:/source)?|agent/source\\.ps1|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}
