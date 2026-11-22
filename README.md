# SecureGenAI — AI Security Assessment & SOC Intelligence

A browser-based demonstration platform for AI security inspection, Shadow AI usage review, SOC log correlation, local security knowledge retrieval and heuristic AI security assessment.

## Features

- **Overview:** security event metrics, severity distribution, event activity and recent findings.
- **AI Guardrails:** local pattern-based prompt injection and risky-content inspection.
- **Sensitive Data:** local detection and masking of common email, phone, credential, token and connection-string patterns.
- **Shadow AI:** CSV-based analysis of approved/unapproved AI application usage and data sensitivity.
- **SOC Log Analyzer:** CSV parsing and simple correlation for repeated failed logins, possible port enumeration and privilege-related activity.
- **SOC Assistant:** structured local alert explanation and investigation guidance.
- **RAG Knowledge:** relevance-based retrieval from a curated local cybersecurity knowledge base with source references.
- **Security Assessment:** weighted heuristic score based on selected risk levels and guardrail effectiveness.
- **Agentic Assistant:** bounded investigation planning; no external actions are performed.
- **Security Policies:** interactive AI governance checklist.

## Technology

- React + TypeScript
- Vite
- Recharts
- PapaParse
- Lucide React
- CSS

All analysis runs in the browser. Uploaded CSV files are parsed locally and are not sent to a server by this application. There is no required API key, external LLM, database, Python runtime or backend service.

## Run locally

Requirements: Node.js 20+ and npm.

```bash
npm install
npm run dev
```

Open the local URL printed by Vite (usually `http://localhost:5173`).

## Production build

```bash
npm run build
npm run preview
```

The production output is generated in `dist/`. The build should include `dist/index.html` and the bundled assets.

## Deploy to Vercel

1. Push this project directory to a new GitHub repository.
2. In Vercel, import that repository.
3. Use these settings:

| Setting | Value |
| --- | --- |
| Framework Preset | Vite |
| Root Directory | Leave empty (repository root) |
| Build Command | `npm run build` |
| Output Directory | `dist` |
| Install Command | `npm install` |

No `vercel.json` is required for this single-page Vite application. Do not set the output directory to `client/dist`.

## CSV schemas

### Shadow AI usage

Required fields: `user`, `app_name`, `approved`, `data_sensitivity`.

Optional fields: `timestamp`, `department`, `action`, `records_shared`.

Example header:

```csv
timestamp,user,department,app_name,approved,data_sensitivity,action,records_shared
```

### SOC logs

Required fields: `source_ip`, `event_type`, `status`.

Optional fields: `timestamp`, `username`, `destination_port`, `details`.

Example header:

```csv
timestamp,username,source_ip,event_type,status,destination_port,details
```

Sample CSV files can be downloaded from the Shadow AI and SOC Log Analyzer modules.

## Important limitations

- The platform uses deterministic regular expressions, thresholds and local retrieval; it does not call an external LLM.
- The RAG Knowledge Assistant performs local relevance retrieval and source-grounded templated output. It is not external generative inference.
- The SOC module analyzes only built-in synthetic data or CSV data supplied by the user. It does not connect to a live SIEM or monitor a real network.
- The AI Security Assessment score is a demonstration heuristic, not a certified or scientifically validated security assessment.
- Pattern-based detection can produce false positives and false negatives. Findings require analyst validation.
- All included sample records and example identifiers are fictional.

## Project references

- [Zscaler — AI Security](https://www.zscaler.com/products-and-solutions/ai-security)
- [Zscaler — AI Guard](https://help.zscaler.com/secure-ai-users/what-ai-guard)
- [OWASP — Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST — AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

## License

Academic demonstration project. Add a license file if you intend to distribute or reuse the code under specific terms.
