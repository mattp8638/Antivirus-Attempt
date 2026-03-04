# TamsilCMS Frontend Starter

Minimal Node frontend (Vite + React + TypeScript) for connecting to backend EDR APIs.

## Quick Start

1. Copy environment template:

```powershell
Copy-Item .env.example .env
```

2. Set `.env` values:

- `VITE_API_BASE_URL` (example: `http://127.0.0.1:8000`)
- `VITE_API_KEY` (must match backend `X-API-Key` dependency)

3. Install and run:

```powershell
npm install
npm run dev
```

4. Open:

- `http://localhost:5173`

## Connected Endpoints

- `GET /edr/alerts`
- `GET /edr/agents`
- `GET /edr/fim/violations`
- `GET /edr/threat-intel/indicators`
- `GET /edr/response/actions`
- `GET /edr/response/playbooks`
- `GET /edr/hunt/examples`
