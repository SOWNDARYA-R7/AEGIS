🛡️ AEGIS-X: Autonomous Agentic SOC
Next-Generation Multi-Agent Security Operations Center with GraphRAG, Digital Twin Simulation, and Live Threat Intel.

Traditional Security Operations Centers (SOCs) rely on static rules, leading to high false-positive rates, alert fatigue, and accidental lockouts of legitimate users. AEGIS-X revolutionizes this by using a high-speed deterministic triage engine combined with a collaborative team of AI Agents. It filters out the noise, simulates attacks in a sandbox, fetches live zero-day context from the internet, and provides a clear recommendation to a human analyst.

🌟 Core Features
High-Speed Triage Engine: Uses Shannon Entropy and Regex heuristics to filter thousands of logs in milliseconds, escalating only genuine anomalies.

Multi-Agent CrewAI Architecture: Deploys a team of specialized AI agents (Threat Intel, Digital Twin, SOC Lead) powered by local LLMs (Ollama/Llama3).

GraphRAG Knowledge Base: Native integration with Neo4j to map threats against the MITRE ATT&CK framework visually and relationally.

Live Zero-Day Search: Integrates the Serper.dev API to actively search the internet for novel payloads, recent CVEs, and live threat intelligence.

Digital Twin Sandbox: Simulates the payload's blast radius against the target architecture (e.g., recognizing that SQL DROP TABLE commands fail on NoSQL MongoDB databases).

Human-in-the-Loop (RLHF): A modern, Google Material Design React dashboard for analysts to review AI reasoning and approve/reject actions to retrain the system.

🏗️ Architecture & Workflow
Ingestion & Triage (FastAPI): Raw access logs are ingested. Safe traffic is dropped; suspicious payloads (Risk > 0.4) trigger the AI crew.

Threat Intel Agent: Maps the payload to MITRE ATT&CK techniques via Neo4j and searches the live web for zero-day context using the Serper API.

Digital Twin Agent: Simulates the payload execution against the system's infrastructure to predict data loss or system impact.

SOC Lead Agent: Synthesizes the intel and simulation data, deciding whether to recommend an IP block or flag it for review (preventing business disruptions).

UI & Verification (React): The analyst reviews the complete incident card, clicks "Approve & Block" or "Reject", and the system records this feedback.

🛠️ Technology Stack
Frontend: React.js, Axios, Google Material Design CSS

Backend: FastAPI (Python), Uvicorn

AI Engine: CrewAI, CrewAI Tools (Serper), Ollama (Llama 3.2:3b local inference)

Knowledge Graph: Neo4j (Cypher)

External APIs: Serper.dev (Google Search API)

🚀 Installation & Setup Guide
Prerequisites
Python 3.10+

Node.js & npm

Neo4j Desktop (Local)

Ollama (For local LLM execution)

Serper.dev Account (For the free Google Search API key)

1. Database & AI Setup
Open Neo4j Desktop, create a local database, set the password, and start the instance (neo4j://127.0.0.1:7687).

Open a terminal and start your local Ollama model:

Bash
ollama run llama3.2:3b
2. Backend Setup (FastAPI & CrewAI)
Clone the repository and create a Python virtual environment:

Bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install dependencies:

Bash
pip install fastapi uvicorn neo4j crewai crewai-tools requests pydantic python-multipart
Set up API Keys: Open agents.py and replace the placeholder with your actual Serper API Key:

Python
os.environ["SERPER_API_KEY"] = "your_serper_api_key_here"
Ingest MITRE Knowledge Graph: Run the automated script to pull the latest STIX data into Neo4j.

Bash
python ingest_mitre.py
Start the FastAPI Server:

Bash
uvicorn main:app --reload --port 8000
3. Frontend Setup (React)
Open a new terminal and navigate to the frontend folder.

Install Node dependencies:

Bash
cd frontend
npm install
Start the React development server:

Bash
npm start
💻 Running the Demo
Open the dashboard at http://localhost:3000.

Click Choose File and upload your log dataset (e.g., cyber.json).

Click Upload and ingest.

Watch the terminal as the CrewAI agents collaborate live, executing internet searches and simulating payloads to investigate the escalated threats.

Review the generated Multi-Agent Intelligence reports on the clean, Google Material Design UI and exercise your Human-in-the-Loop controls.

Reinforcement learning will be working by learning its mistake.
