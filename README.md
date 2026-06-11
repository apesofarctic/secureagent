# SecureAgent — AI-Powered Virtual CISO for Startups

SecureAgent is an AI agent that acts as a virtual CISO (Chief Information Security
Officer) for early-stage startups. A founder describes their company once and the agent
assesses their security posture, generates tailored policies, builds a phased remediation
roadmap, and tracks implementation progress over time.

**This is not a chatbot.** It is a stateful agent that reasons through a security
framework, writes findings to MongoDB, generates policy documents, and maintains
persistent state across conversations.

## Demo

🎥 [Watch the demo video](#) ← add link after recording

🚀 [Live Demo](#) ← add Cloud Run URL after deployment

## What It Does

1. **Assesses** cybersecurity posture using the NIST CSF 2.0 framework
2. **Identifies** gaps and scores risks by severity (CRITICAL / HIGH / MEDIUM / LOW)
3. **Generates** tailored policy documents (BYOD, Incident Response, Access Control, Data Handling)
4. **Creates** a phased remediation roadmap (30 / 60 / 90 / 180 days)
5. **Tracks** implementation progress — mark items complete, recalculates security score

## Architecture

```
User (Founder)
      │
      ▼
Google ADK Agent (Python)
  LlmAgent (Gemini 2.5 Flash)
  System prompt encodes NIST CSF 2.0 logic
      │
      ▼
MongoDB MCP Server (via npx)
  McpToolset with StdioServerParameters
      │
      ▼
MongoDB Atlas (M0 Free Tier)
  Database: secureagent
  Collections: companies, assessments, risks, policies, roadmap_items
```

**Deployment:** Google Cloud Run via `adk deploy cloud_run`

## Tech Stack

| Component | Technology |
|-----------|-----------|
| LLM | Gemini 2.5 Flash |
| Agent Framework | Google ADK (Python) |
| Database MCP | MongoDB MCP Server |
| Database | MongoDB Atlas M0 (free) |
| Deployment | Google Cloud Run |
| Package Manager | uv |

## Setup Instructions

### Prerequisites
- Python 3.11+
- Node.js v18+
- Google Cloud account with Vertex AI enabled
- MongoDB Atlas account (free)

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/secureagent.git
cd secureagent
```

### 2. Set up Python environment
```bash
uv venv
source .venv/bin/activate   # Mac/Linux
# or .venv\Scripts\activate on Windows
uv add google-adk
```

### 3. Configure Google Cloud
```bash
gcloud auth login
gcloud config set project YOUR_GCP_PROJECT_ID
gcloud auth application-default login
```

### 4. Set up `.env`
```bash
cp .env.example .env
# Edit .env with your GCP project ID
```

### 5. Add MongoDB connection string
Edit `secureagent_agent/agent.py` and replace `YOUR_CONNECTION_STRING_HERE` with your
MongoDB Atlas connection string.

### 6. Run locally
```bash
adk web
```

Open http://localhost:8000 and select `secureagent_agent`.

## MongoDB Schema

**companies** — Company profile with tech stack, data types, compliance needs

**assessments** — One document per NIST CSF control, with score (0–4), severity,
finding description, and recommendation

**risks** — Identified risks with likelihood, impact, and mitigation status

**policies** — Full text of generated policy documents (BYOD, IR Plan, etc.)

**roadmap_items** — Phased tasks (30/60/90/180 day) with status tracking

## NIST CSF 2.0 Framework

The agent reasons through 4 assessment domains:

1. **Govern & Identify** — Asset inventory, data classification, compliance mapping
2. **Protect** — MFA, access control, encryption, BYOD, backups, training (35% weight)
3. **Detect** — Logging, monitoring, vulnerability scanning (25% weight)
4. **Respond & Recover** — Incident response, communications, business continuity

Each control scored 0–4. Overall score = weighted average. Letter grades: A(3.5+), B(2.75+),
C(2.0+), D(1.0+), F(<1.0)

## License

MIT
