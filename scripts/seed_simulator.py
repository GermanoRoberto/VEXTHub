import asyncio
import asyncpg
import uuid
import random

# Configurações do Banco de Dados (Alinhado com .env default)
DB_URL = "postgresql://vexthub:vexthub@localhost:5432/vexthub"

TENANT_ID = "00000000-0000-0000-0000-000000000001"
TENANT_NAME = "Simulação Interna (2.7k)"
TENANT_SLUG = "simulacao-interna"

NUM_UNITS = 27
MACHINES_PER_UNIT = 100

async def seed():
    print(f"Conectando ao banco em {DB_URL}...")
    try:
        conn = await asyncpg.connect(DB_URL)
    except Exception as e:
        print(f"ERRO: Não foi possível conectar ao PostgreSQL: {e}")
        return

    print("--- INICIANDO POPULAÇÃO DE DADOS ---")

    # 1. Garantir Tenant
    await conn.execute("""
        INSERT INTO public.tenants (id, name, slug)
        VALUES ($1, $2, $3)
        ON CONFLICT (id) DO NOTHING
    """, uuid.UUID(TENANT_ID), TENANT_NAME, TENANT_SLUG)

    # 2. Criar Unidades
    unit_ids = []
    print(f"Criando {NUM_UNITS} unidades...")
    for i in range(1, NUM_UNITS + 1):
        unit_name = f"Unidade Tática {i:02d}"
        desc = f"Ponto de Presença Regional {i}"
        
        uid = await conn.fetchval("""
            INSERT INTO public.units (tenant_id, name, description)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, name) DO UPDATE SET description = EXCLUDED.description
            RETURNING id
        """, uuid.UUID(TENANT_ID), unit_name, desc)
        unit_ids.append((uid, unit_name))

    # 3. Criar Máquinas
    print(f"Criando {NUM_UNITS * MACHINES_PER_UNIT} máquinas (isso pode levar alguns segundos)...")
    
    machines_data = []
    for uid, uname in unit_ids:
        for m in range(1, MACHINES_PER_UNIT + 1):
            mid = f"SIM-{uname.replace(' ', '-')}-{m:03d}".upper()
            hostname = f"WS-{uname[-2:]}-{m:03d}"
            
            os_names = ["Windows 10 Pro", "Windows 11 Enterprise", "Ubuntu 22.04 LTS", "Windows Server 2022"]
            cpus = ["Intel i7-12700K", "AMD Ryzen 9 5900X", "Intel i5-11400", "Xeon Gold 6248R"]
            rams = ["16GB", "32GB", "64GB", "8GB"]
            
            machines_data.append((
                mid,
                uuid.UUID(TENANT_ID),
                uid,
                hostname,
                f"SN-{random.randint(10000, 99999)}",
                uname,
                random.choice(os_names),
                random.choice(cpus),
                random.choice(rams),
                "v4.0.0-sim"
            ))

    # Inserção em massa
    await conn.executemany("""
        INSERT INTO public.machines 
        (id, tenant_id, unit_id, hostname, serial_number, unit, os_name, cpu_info, ram_total, agent_version)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (id) DO UPDATE SET
            last_pulse = now()
    """, machines_data)

    print("--- POPULAÇÃO CONCLUÍDA ---")
    print(f"Total: {NUM_UNITS} Unidades | {len(machines_data)} Agentes")
    
    await conn.close()

if __name__ == "__main__":
    asyncio.run(seed())
