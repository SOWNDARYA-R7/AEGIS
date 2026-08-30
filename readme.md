# 🛡️ Autonomous Agentic SOC: Multi-Agent GraphRAG & Closed-Loop Response

An autonomous Security Operations Center (SOC) MVP built for rapid threat detection, triage, and mitigation. This system uses local LLMs, a MITRE-mapped Knowledge Graph (GraphRAG), and Reinforcement Learning from Human Feedback (RLHF) to isolate threats without manual intervention.

## 🧠 Core Architecture & File Structure
Our project consists of 5 core components that work together in a real-time pipeline:

| File Name | Role | Description |
| :--- | :--- | :--- |
| `app.py` | Target Application | The vulnerable enterprise portal (Endpoint: `/search`). It intercepts incoming traffic and generates live JSON logs. |
| `agents.py` | AI Brain | Contains the 3 autonomous agents (Triage, Investigate, Detect) that process logs and analyze attacker intent. |
| `graph_engine.py` | Knowledge Graph | The GraphRAG system mapped to MITRE ATT&CK rules. Eliminates static rules by linking patterns dynamically. |
| `verify.py` | Auto-Mitigation | Applies containment by blocking attacker IPs and actively pinging the target to verify isolation (Closed-loop). |
| `dashboard.py` | SOC UI (Streamlit) | The live visual dashboard for monitoring agents, viewing MITRE alignment, and providing RLHF feedback. |

## 🤖 How the Multi-Agent System Works
We use a **Single Shared LLM (Llama 3.1)** powering 3 distinct Agentic roles:
1. **Triage Agent (Fast Filter):** Uses heuristic risk-scoring and Regex to filter noise instantly without wasting LLM compute.
2. **Investigation Agent (Contextualizer):** Queries the local Llama 3.1 model to analyze the payload and summarize the "Attacker's Intent".
3. **Threat Detection Agent (GraphRAG Validator):** Cross-references the extracted payload against the MITRE GraphRAG database to identify known TTPs (Tactics, Techniques, and Procedures).

## 📡 Live Log Generation
We do not use static datasets like Kaggle. The logs are **100% Real-Time**. 
Whenever a user interacts with `app.py`, a `@app.before_request` hook captures the IP, Timestamp, HTTP Method, and Payload, appending it directly to `access_logs.json`. The SOC dashboard streams this live.

## 🔄 Reinforcement Learning from Human Feedback (RLHF)
When a Novel/Zero-Day attack bypasses the GraphRAG, the system flags it and waits for Human-in-the-Loop intervention. The SOC Analyst can:
*   **Approve (+1 Reward):** The AI learns the new signature and creates a new node in the GraphRAG dynamically.
*   **Mark Safe (-1 Penalty):** The AI whitelists the payload.

---

## ⚙️ Prerequisites & Downloads
*   **Python 3.10+**: Installed and added to PATH.
*   **Ollama**: Running locally with the `llama3.1` model.
    ```bash
    ollama run llama3.1
    ```

## 🚀 Installation & Setup
1. **Clone the repository and activate virtual environment:**
    ```bash
    cd hackathon_soc
    python -m venv venv
    venv\Scripts\activate
    ```
2. **Install dependencies:**
    ```bash
    pip install flask networkx requests streamlit langchain langchain-community
    ```

## 🎮 Live Demo Execution Steps
Run the Target App and SOC Dashboard simultaneously in two separate terminals (ensure `venv` is active in both).

**Terminal 1:** `python app.py` (Runs on port 5000)
**Terminal 2:** `streamlit run dashboard.py` (Runs on port 8501)

### Test Case 1: SQL Injection (Known Threat)
1. Go to `http://127.0.0.1:5000` and enter: `' OR '1'='1`
2. Go to the Dashboard and click **"Poll Latest Log & Run Pipeline"**.
3. **Result:** The system identifies **T1190**, autonomously blocks the IP, and verifies containment (HTTP 403 Forbidden).

### Test Case 2: Cross-Site Scripting (XSS)
1. Delete `access_logs.json` to clear previous sessions.
2. Refresh the web app and enter: `<script>alert('hack')</script>`
3. Run the pipeline in the dashboard.
4. **Result:** The XSS script is neutralized. If you try to access the web app again, you will be blocked (403 Access Denied) because the Mitigation Agent isolated your IP.

### Test Case 3: Zero-Day Attack & RLHF
1. Delete `access_logs.json` and restart `app.py`.
2. Enter a novel payload: `UNKNOWN_FUZZ_999_SYSTEM_HALT`
3. Run the pipeline.
4. **Result:** GraphRAG detects an anomaly but finds no known signature. The UI prompts the analyst for RLHF to dynamically update the Knowledge Graph.