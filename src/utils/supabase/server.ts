import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE || "";

function createChainableMockProxy(isQuery = false) {
  const handler: ProxyHandler<any> = {
    get(_target, prop) {
      if (prop === 'auth') return {
        getUser: async () => ({ data: { user: { id: '00000000-0000-0000-0000-000000000000', email: 'guest@local' } }, error: null }),
        getSession: async () => ({ data: { session: null }, error: null }),
        onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => {} } } })
      };
      if (prop === 'then') {
        if (!isQuery) return undefined;
        return (resolve: (...args: unknown[]) => unknown) => resolve({ data: null, error: new Error("Simulation mode active") });
      }
      return createChainableMockProxy(true);
    },
    apply() {
      return createChainableMockProxy(true);
    }
  };
  return new Proxy(() => {}, handler);
}

export const createClient = async () => {
  const isSimulation = process.env.NEXT_PUBLIC_SIMULATION_MODE === 'true';
  if (!supabaseUrl || !supabaseKey || isSimulation) {
    return createChainableMockProxy();
  }

  const cookieStore = await cookies();

  return createServerClient(
    supabaseUrl,
    supabaseKey,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll()
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) => cookieStore.set(name, value, options))
          } catch {
            // Ignorado em Server Components
          }
        },
      },
    },
  );
};
