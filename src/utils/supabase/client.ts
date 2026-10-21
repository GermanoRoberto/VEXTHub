import { createBrowserClient } from "@supabase/ssr";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE || "";

export const createClient = () => {
  const isSimulation = process.env.NEXT_PUBLIC_SIMULATION_MODE === 'true';
  
  if (!supabaseUrl || !supabaseKey || isSimulation) {
    if (isSimulation) {
      console.info("VextHub: Modo Simulação Ativo. Supabase desativado no frontend.");
    } else {
      console.warn("Supabase credentials missing. Using Mock Client.");
    }
    return new Proxy({} as any, {
      get: (_, prop) => {
        if (prop === 'auth') return { 
          getUser: async () => ({ data: { user: { id: '00000000-0000-0000-0000-000000000000', email: 'guest@local' } }, error: null }),
          getSession: async () => ({ data: { session: null }, error: null }),
          onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => {} } } })
        };
        if (prop === 'channel') return () => ({
          on: function() { return this; },
          subscribe: () => ({ unsubscribe: () => {} }),
          unsubscribe: () => {}
        });
        if (prop === 'from') return () => ({ 
          select: () => ({ 
            eq: () => ({ 
              limit: () => ({ 
                single: async () => ({ data: {}, error: null }), 
                maybeSingle: async () => ({ data: {}, error: null }) 
              }),
              maybeSingle: async () => ({ data: {}, error: null }),
              order: () => ({ limit: async () => ({ data: [], error: null }) })
            }),
            maybeSingle: async () => ({ data: {}, error: null }),
            order: () => ({ limit: async () => ({ data: [], error: null }) })
          }),
          insert: () => ({ select: () => ({ single: async () => ({ data: {}, error: null }) }) }),
          upsert: () => ({ select: () => ({ single: async () => ({ data: {}, error: null }) }) })
        });
        return () => ({});
      }
    });
  }
  return createBrowserClient(supabaseUrl, supabaseKey);
};
