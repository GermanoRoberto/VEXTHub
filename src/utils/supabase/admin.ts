import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
const supabaseAdminKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

function createChainableMockProxy() {
  const handler: ProxyHandler<any> = {
    get(_target, prop) {
      if (prop === 'then') {
        return (resolve: (...args: unknown[]) => unknown) => resolve({ data: null, error: new Error("Simulation mode active") });
      }
      return new Proxy(() => {}, handler);
    },
    apply() {
      return new Proxy(() => {}, handler);
    }
  };
  return new Proxy(() => {}, handler);
}

export const supabaseAdmin = (supabaseUrl && supabaseAdminKey && process.env.NEXT_PUBLIC_SIMULATION_MODE !== 'true') 
  ? createClient(supabaseUrl, supabaseAdminKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    })
  : createChainableMockProxy();

