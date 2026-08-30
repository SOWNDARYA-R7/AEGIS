from agents import run_investigation_pipeline
import json
import math
import re
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase
from pydantic import BaseModel

app = FastAPI(title="AEGIS-X Autonomous SOC Core")

# Allow React Frontend Connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Neo4j Setup
NEO4J_URI = "neo4j://127.0.0.1:7687"
NEO4J_AUTH = ("neo4j", "Sound#777") # Keep your password

def get_neo4j_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)

# --- Helper: Triage Scoring Logic ---
def calculate_shannon_entropy(text: str) -> float:
    """Calculates randomness in string payloads to detect obfuscated attacks."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return round(entropy, 2)

def evaluate_payload_triage(payload: str, endpoint: str) -> dict:
    """Fast, lightweight triage check without hitting heavy LLMs."""
    suspicious_patterns = [
        r"('|--|;|\/\*|\*\/|@@|char|nchar|varchar)", # SQLi markers
        r"(<script|alert\(|onerror=|onload=|<img)",  # XSS markers
        r"(\.\.\/|\/etc\/passwd|cmd\.exe|\/bin\/sh)",# Path Traversal / Command Injection
        r"(DROP\s+TABLE|SELECT\s+.*FROM|UNION\s+SELECT)" # SQL Commands
    ]
    
    score = 0.0
    matched_flags = []
    
    for pattern in suspicious_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            score += 0.4
            matched_flags.append(pattern)
            
    entropy = calculate_shannon_entropy(payload)
    if entropy > 4.2:
        score += 0.3
        matched_flags.append(f"High Entropy ({entropy})")
        
    is_suspicious = score >= 0.4
    return {
        "is_suspicious": is_suspicious,
        "risk_score": min(score, 1.0),
        "flags": matched_flags,
        "entropy": entropy
    }

# --- Routes ---

@app.get("/")
def health_check():
    return {"status": "AEGIS-X SOC Engine Active", "graph_connected": True}

@app.post("/api/upload-logs")
def upload_logs(file: UploadFile = File(...)):
    try:
        content = file.file.read()
        logs = json.loads(content.decode("utf-8"))
        
        triage_summary = {
            "total_logs": len(logs),
            "clean_logs": 0,
            "threats_escalated": 0,
            "investigation_reports": []
        }
        
        for entry in logs:
            # Map both old format and new cyber.json format
            raw_payload = entry.get("Payload Data", entry.get("payload", ""))
            endpoint = entry.get("Traffic Type", entry.get("endpoint", "Unknown"))
            ip = entry.get("Source IP Address", entry.get("ip", "Unknown"))
            
            # Base regex and entropy check
            triage_result = evaluate_payload_triage(raw_payload, endpoint)
            
            # Incorporate cyber.json specific threat indicators
            anomaly_score = float(entry.get("Anomaly Scores", 0))
            if entry.get("Malware Indicators") == "IoC Detected" or anomaly_score > 80.0:
                triage_result["is_suspicious"] = True
                triage_result["risk_score"] = round(max(triage_result["risk_score"], anomaly_score / 100), 2)
                triage_result["flags"].append(f"Network Anomaly ({anomaly_score}%)")
            
            if triage_result["is_suspicious"]:
                triage_summary["threats_escalated"] += 1
                
                # Standardize entry format for the frontend
                clean_entry = {
                    "ip": ip,
                    "endpoint": endpoint,
                    "payload": raw_payload
                }
                
                triage_summary["investigation_reports"].append({
                    "raw_entry": clean_entry,
                    "triage_details": triage_result,
                    "soc_lead_recommendation": "Pending AI Deep Investigation..."
                })
            else:
                triage_summary["clean_logs"] += 1

        # Run AI only on the first critical threat to save time during the demo
        if triage_summary["threats_escalated"] > 0:
            target = triage_summary["investigation_reports"][0]["raw_entry"]
            print(f"\n[!] Triggering AI for IP: {target['ip']}")
            agent_report = run_investigation_pipeline(target["payload"], target["endpoint"])
            triage_summary["investigation_reports"][0]["soc_lead_recommendation"] = str(agent_report)
                
        return triage_summary
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process log file: {str(e)}")
# Test Route to Query MITRE Graph
@app.get("/api/mitre-technique/{technique_id}")
def get_mitre_technique(technique_id: str):
    driver = get_neo4j_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (t:Technique) WHERE t.mitre_id = $tech_id RETURN t.name AS name, t.description AS description",
            tech_id=technique_id
        )
        record = result.single()
    driver.close()
    
    if not record:
        raise HTTPException(status_code=404, detail="Technique not found in Neo4j")
    return {"name": record["name"], "description": record["description"]}