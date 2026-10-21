import requests
import json
import sys

BASE_URL = "http://localhost:8000/api"

def test_unauthorized_access():
    print("--- Teste 1: Acesso Não Autorizado ---")
    # Endpoint de resumo não deveria ser público
    endpoints = [
        "/units/summary",
        "/agents/installer/APEX-GLOBAL",
        "/alerts/"
    ]
    
    for ep in endpoints:
        print(f"Verificando {ep} sem token...")
        try:
            r = requests.get(f"{BASE_URL}{ep}")
            if r.status_code == 200:
                print(f" [!] FALHA DE SEGURANÇA: {ep} está exposto publicamente!")
            else:
                print(f" [OK] {ep} retornou {r.status_code}")
        except Exception as e:
            print(f" [X] Erro ao conectar: {e}")

def test_malicious_input():
    print("\n--- Teste 2: Input Malicioso (XSS/Payload) ---")
    # Tentar registrar um agente com hostname malicioso
    payload = {
        "hostname": "<script>alert('XSS')</script>",
        "unit_token": "APEX-GLOBAL",
        "ip_address": "127.0.0.1",
        "os_info": "Linux",
        "cpu_usage": 0,
        "memory_usage": 0
    }
    
    print("Enviando payload XSS para /agents/register...")
    try:
        r = requests.post(f"{BASE_URL}/agents/register", json=payload)
        if r.status_code == 200:
            print(" [!] FALHA: Backend aceitou hostname com script tags!")
        else:
            print(f" [OK] Backend rejeitou ou tratou o input (Status: {r.status_code})")
    except Exception as e:
        print(f" [X] Erro ao conectar: {e}")

def test_token_invalidation():
    print("\n--- Teste 3: Invalidação de Sessão (Logout) ---")
    
    # 1. Login para obter token
    login_payload = {
        "username": "master",
        "password": "master_apex123"
    }
    
    try:
        print("Realizando login como 'master'...")
        # Nota: O backend aceita form-data para /token (OAuth2)
        r = requests.post(f"{BASE_URL}/auth/login", data=login_payload) # Tenta a rota de compatibilidade
        if r.status_code != 200:
            # Tenta a rota /token padrão
            r = requests.post(f"http://localhost:8000/token", data=login_payload)
            
        if r.status_code != 200:
            print(f" [X] Erro no login (Status: {r.status_code}). Certifique-se que o backend está rodando.")
            return

        token = r.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}
        print(" [OK] Token obtido com sucesso.")

        # 2. Testar acesso com o token
        r_check = requests.get(f"{BASE_URL}/units/", headers=headers)
        if r_check.status_code != 200:
            print(f" [X] Erro ao acessar rota protegida ANTES do logout (Status: {r_check.status_code})")
            return
        print(" [OK] Acesso à rota protegida confirmado.")

        # 3. Realizar Logout
        print("Realizando logout (Invalidação via Blacklist)...")
        r_logout = requests.post(f"{BASE_URL}/auth/logout", headers=headers)
        if r_logout.status_code != 200:
            print(f" [!] Erro ao realizar logout (Status: {r_logout.status_code})")
            return
        print(" [OK] Logout realizado.")

        # 4. Tentar usar o mesmo token novamente
        print("Tentando usar o token revogado...")
        r_final = requests.get(f"{BASE_URL}/units/", headers=headers)
        if r_final.status_code == 401:
            print(" [OK] SUCESSO: Token foi invalidado corretamente pelo backend.")
        else:
            print(f" [!] FALHA: O token ainda é aceito pelo backend (Status: {r_final.status_code})!")

    except Exception as e:
        print(f" [X] Erro durante o teste de invalidação: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        test_unauthorized_access()
        test_malicious_input()
        test_token_invalidation()
    else:
        print("Script de auditoria de segurança gerado. Use 'run' para executar.")
