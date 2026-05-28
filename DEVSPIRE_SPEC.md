# DevSpire — Especificação Técnica Completa

## Visão Geral
Plataforma de pentesting e análise de segurança automatizada. O usuário insere uma URL no terminal do site e recebe um relatório completo de vulnerabilidades em PDF.

## Estrutura do Projeto

```
devspire/
├── index.html          (já existe — frontend)
├── premium.css         (já existe)
├── premium.js          (já existe)
├── logo.jpeg           (já existe)
├── vercel.json         (já existe)
├── api/                (CRIAR — backend Python)
│   ├── app.py          (FastAPI principal)
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py       (orquestrador de scans)
│   │   ├── port_scan.py    (scan de portas com socket)
│   │   ├── headers.py      (análise de headers HTTP)
│   │   ├── ssl_check.py    (verificação TLS/SSL)
│   │   ├── cors_check.py   (teste CORS misconfiguration)
│   │   ├── dir_enum.py     (enumeração de diretórios)
│   │   ├── subdomain.py    (enumeração de subdomínios)
│   │   ├── js_analysis.py  (análise de JS por info disclosure)
│   │   ├── tech_detect.py  (detecção de tecnologias)
│   │   ├── dns_check.py    (registros DNS, SPF, DMARC)
│   │   └── waf_detect.py   (detecção de WAF/CDN)
│   ├── report/
│   │   ├── __init__.py
│   │   ├── generator.py    (gera relatório JSON)
│   │   ├── pdf_report.py   (gera PDF formatado)
│   │   └── template.html   (template HTML do relatório)
│   ├── wordlists/
│   │   └── common.txt      (wordlist para dir_enum)
│   ├── requirements.txt
│   └── Dockerfile
```

## Backend — API Endpoints

### POST /api/scan
Inicia um scan. Retorna scan_id.
```json
Request:  { "target": "example.com", "mode": "full" }
Response: { "scan_id": "abc123", "status": "running" }
```

### GET /api/scan/{scan_id}
Retorna status e resultados parciais/completos.
```json
Response: {
  "scan_id": "abc123",
  "status": "completed",  // running | completed | error
  "progress": 100,
  "target": "example.com",
  "started_at": "2026-05-28T10:00:00Z",
  "completed_at": "2026-05-28T10:03:00Z",
  "results": {
    "summary": { "critical": 0, "high": 2, "medium": 5, "low": 3, "info": 8 },
    "modules": { ... }
  }
}
```

### GET /api/report/{scan_id}
Retorna PDF do relatório para download.

### GET /api/health
Retorna status da API.

## Módulos do Scanner

### 1. port_scan.py — Scan de Portas
- Scan TCP das top 100 portas mais comuns
- Usa socket Python (sem dependência externa)
- Identifica serviço por banner grabbing
- Output: lista de portas abertas com serviço detectado

### 2. headers.py — Análise de Headers HTTP
- Verifica headers de segurança presentes/ausentes:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
  - Cross-Origin-Opener-Policy
  - Cross-Origin-Resource-Policy
- Detecta headers que vazam info: Server, X-Powered-By, X-AspNet-Version
- Classifica severidade de cada finding

### 3. ssl_check.py — Verificação TLS/SSL
- Verifica versão do TLS (1.0, 1.1, 1.2, 1.3)
- Validade do certificado (expiração, CN, SAN)
- Cipher suites fracas
- HSTS preload
- Certificate chain

### 4. cors_check.py — Teste CORS
- Envia requests com Origin malicioso (evil.com, null, localhost)
- Verifica se Access-Control-Allow-Origin reflete qualquer origin
- Verifica Access-Control-Allow-Credentials
- Classifica: seguro / misconfigured / wildcard

### 5. dir_enum.py — Enumeração de Diretórios
- Wordlist embutida (top 200 paths críticos)
- Paths testados: /.env, /.git/config, /admin, /api/docs, /swagger.json, /phpinfo.php, etc.
- Filtra falsos positivos por tamanho (SPA detection)
- Classifica por status code (200, 301, 403)

### 6. subdomain.py — Enumeração de Subdomínios
- Testa lista de subdomínios comuns: api, admin, dev, staging, cdn, mail, etc.
- Resolve DNS para verificar existência
- Testa HTTPS de cada subdomínio encontrado
- Retorna status code e tamanho

### 7. js_analysis.py — Análise de JavaScript
- Extrai URLs de scripts carregados na página
- Busca padrões sensíveis nos JS:
  - URLs de API (endpoints internos)
  - Tokens/API keys hardcoded
  - Variáveis de ambiente
  - URLs de ambientes dev/staging
  - Sentry DSN
  - Firebase/AWS configs
- Classifica cada achado por severidade

### 8. tech_detect.py — Detecção de Tecnologias
- Analisa headers, meta tags, scripts, cookies
- Detecta: framework (React, Angular, Vue, Next.js), CMS (WordPress, Magnolia), CDN (Cloudflare, CloudFront), WAF, linguagem backend
- Retorna stack tecnológico completo

### 9. dns_check.py — Análise DNS
- Registros A, AAAA, MX, TXT, NS, CNAME
- Verifica SPF, DKIM, DMARC
- Detecta email spoofing risk
- Zone transfer attempt (AXFR)

### 10. waf_detect.py — Detecção de WAF/CDN
- Identifica Cloudflare, AWS WAF, Akamai, Imperva, etc.
- Testa rate limiting
- Verifica bypass potencial

## Engine (engine.py) — Orquestrador

```python
# Pseudocódigo do fluxo
async def run_scan(target, mode="full"):
    scan = create_scan_record(target)
    
    # Fase 1: Reconhecimento (paralelo)
    dns_results = await dns_check(target)
    tech_results = await tech_detect(target)
    waf_results = await waf_detect(target)
    update_progress(scan, 20)
    
    # Fase 2: Enumeração (paralelo)
    port_results = await port_scan(target)
    subdomain_results = await subdomain_enum(target)
    dir_results = await dir_enum(target)
    update_progress(scan, 50)
    
    # Fase 3: Análise de Vulnerabilidades (paralelo)
    header_results = await headers_check(target)
    ssl_results = await ssl_check(target)
    cors_results = await cors_check(target)
    js_results = await js_analysis(target)
    update_progress(scan, 90)
    
    # Fase 4: Relatório
    report = generate_report(all_results)
    pdf = generate_pdf(report)
    update_progress(scan, 100)
    
    return report
```

## Relatório PDF — Estrutura

1. **Capa** — Logo DevSpire, nome do alvo, data, classificação geral
2. **Executive Summary** — Resumo para C-level, score de segurança (0-100)
3. **Tabela de Findings** — Ordenada por severidade (Critical > High > Medium > Low > Info)
4. **Detalhes por Módulo** — Cada finding com:
   - Descrição
   - Evidência (request/response)
   - Impacto
   - Remediação recomendada
   - CVSS score
   - CWE reference
5. **Stack Tecnológico** — Tecnologias detectadas
6. **Subdomínios** — Mapa de subdomínios encontrados
7. **Recomendações Gerais** — Top 5 ações prioritárias
8. **Disclaimer** — Aviso legal sobre uso autorizado

## Frontend — Alterações Necessárias

### index.html
- Conectar terminal ao backend real (já tem a lógica, só apontar DEVSPIRE_API)
- Adicionar barra de progresso no terminal
- Adicionar botão de download do PDF quando scan completar
- Adicionar validação de input (aceitar domínio ou IP, rejeitar localhost/IPs privados)

### Terminal UX
- Mostrar progresso em tempo real (polling a cada 3s já implementado)
- Cada módulo mostra resultados conforme completa
- No final: score de segurança + botão download PDF

## Stack Tecnológica

- **Backend**: Python 3.11+ com FastAPI
- **Async**: asyncio + httpx para requests paralelos
- **PDF**: reportlab ou weasyprint
- **DNS**: dnspython
- **SSL**: ssl (stdlib) + cryptography
- **Deploy**: Vercel (frontend) + Railway/Render (backend API)
- **CORS**: FastAPI CORSMiddleware (permitir domínio do frontend)

## Segurança da Própria Plataforma

- Rate limiting: max 5 scans por IP por hora
- Input validation: só aceitar domínios/IPs públicos válidos
- Não permitir scan de localhost, 127.0.0.1, IPs privados (10.x, 192.168.x, 172.16-31.x)
- Timeout de 5 minutos por scan
- Sanitizar todos os outputs (prevenir XSS no relatório)
- API key opcional para uso comercial
- Logs de auditoria de todos os scans

## Deploy

### Frontend (Vercel) — já configurado
- Só precisa atualizar DEVSPIRE_API no index.html para apontar ao backend

### Backend (Railway ou Render)
```bash
cd api/
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5000
```

### Variáveis de Ambiente
```
ALLOWED_ORIGINS=https://devspire.ie
RATE_LIMIT=5/hour
MAX_SCAN_TIMEOUT=300
```

## Comandos para Próxima Conversa

Iniciar nova conversa com:
```
Leia o arquivo Desktop/devspire/DEVSPIRE_SPEC.md e implemente o backend completo da plataforma DevSpire conforme a especificação. Comece criando a pasta api/ com todos os módulos do scanner, o engine orquestrador, a API FastAPI, e a geração de relatório PDF. Depois conecte o frontend ao backend.
```
