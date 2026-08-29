import json
import re
from langchain_community.llms import Ollama
from graph_engine import graph_db

# Initialize connection to your local Ollama model
# Ensure Ollama is running in the background before executing the final project
try:
    local_llm = Ollama(model="llama3.1")
except Exception as e:
    print(f"Warning: Ensure Ollama is running. Error: {e}")
    local_llm = None


def triage_agent(log_entry: dict) -> dict:
    """Stage 1: Filters noise and assigns a risk score."""
    risk_score = 0.0
    reasons = []

    # Combine query parameters and body to check for payloads
    raw_payload = str(log_entry.get("query_params", "")) + str(log_entry.get("body", ""))

    # Fast heuristic check before sending to LLM (Saves inference time)
    if re.search(r"('|\"|;|--|/\*|<script|UNION|SELECT)", raw_payload, re.IGNORECASE):
        risk_score += 8.0
        reasons.append("High entropy or SQL/XSS characters detected")

    if log_entry.get("path") in ["/admin", "/search", "/login"]:
        risk_score += 1.5
        reasons.append("Targeting Critical Endpoint")

    is_escalated = risk_score >= 7.0

    return {
        "escalate": is_escalated,
        "risk_score": min(risk_score, 10.0),
        "reasons": reasons,
        "log": log_entry,
    }


def investigation_agent(triage_result: dict) -> dict:
    """Stage 2: Extracts context (Who, What, When) for the GraphRAG."""
    log = triage_result["log"]
    payload = log.get("query_params", {}).get("q") or log.get("body", "")

    investigation_report = {
        "who": {
            "source_ip": log.get("client_ip"),
            "user_agent": log.get("headers", {}).get("User-Agent", "Unknown"),
        },
        "what": {
            "target_endpoint": log.get("path"),
            "payload_observed": payload,
            "http_method": log.get("method"),
        },
        "when": {"timestamp": log.get("timestamp")},
    }
    
    # Optional: Use LLM to summarize the attacker's intent
    if local_llm and payload:
        try:
            prompt = f"Briefly explain the intent of this web payload in one sentence: {payload}"
            intent = local_llm.invoke(prompt).strip()
            investigation_report["what"]["llm_intent_analysis"] = intent
        except:
            investigation_report["what"]["llm_intent_analysis"] = "LLM analysis unavailable."

    return investigation_report


def threat_detection_agent(investigation_data: dict) -> dict:
    """Stage 3: Queries the GraphRAG to detect known attacks or flag novel ones."""
    payload = investigation_data["what"]["payload_observed"]
    
    # Query the MITRE GraphRAG engine we built in Step 3
    graph_match = graph_db.query_pattern(payload)

    detection_summary = {
        "investigation": investigation_data,
        "graph_rag_result": graph_match,
        "requires_human_review": not graph_match.get("found", False),
    }

    return detection_summary