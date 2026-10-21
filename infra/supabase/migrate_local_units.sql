-- Script de Migração para Unidades Existentes (Ambiente Local)
-- Aplica as novas colunas de geolocalização e tokens

-- 1. Adiciona as colunas caso ainda não existam
ALTER TABLE public.units ADD COLUMN IF NOT EXISTS city TEXT;
ALTER TABLE public.units ADD COLUMN IF NOT EXISTS state TEXT;
ALTER TABLE public.units ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION;
ALTER TABLE public.units ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION;
ALTER TABLE public.units ADD COLUMN IF NOT EXISTS agent_key TEXT UNIQUE;

-- 2. Define o valor padrão para novos registros (caso o ALTER TABLE não tenha aplicado)
ALTER TABLE public.units ALTER COLUMN agent_key SET DEFAULT 'v_key_' || encode(gen_random_bytes(16), 'hex');

-- 3. Gera Agent Keys para unidades que já existiam e estão vazias
UPDATE public.units 
SET agent_key = 'v_key_' || encode(gen_random_bytes(16), 'hex')
WHERE agent_key IS NULL;

-- 4. Exemplo de como você pode popular as cidades das suas unidades atuais manualmente:
-- UPDATE public.units SET city = 'São Paulo', state = 'SP', latitude = -23.5505, longitude = -46.6333 WHERE name = 'Unidade Exemplo';

DO $$
BEGIN
  RAISE NOTICE 'Migração de unidades concluída com sucesso.';
END $$;
