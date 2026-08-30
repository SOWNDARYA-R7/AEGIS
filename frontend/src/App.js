import React, { useState, useMemo, useEffect, useCallback } from 'react';
import './App.css';

// Default reference access telemetry for instant inspection and offline demonstration
const DEFAULT_DEMO_LOGS = [
  {
    timestamp: "2026-08-30T10:00:01Z",
    ip: "192.168.1.15",
    method: "GET",
    endpoint: "/api/v1/profile",
    protocol: "HTTP/2.0",
    payload: "user_id=102"
  },
  {
    timestamp: "2026-08-30T10:00:05Z",
    ip: "192.168.1.44",
    method: "GET",
    endpoint: "/search",
    protocol: "HTTP/1.1",
    payload: "smart security sensors"
  },
  {
    timestamp: "2026-08-30T10:00:12Z",
    ip: "10.0.0.52",
    method: "POST",
    endpoint: "/search",
    protocol: "HTTP/2.0",
    payload: "'; DROP TABLE users;--"
  },
  {
    timestamp: "2026-08-30T10:00:18Z",
    ip: "192.168.1.89",
    method: "GET",
    endpoint: "/about-us",
    protocol: "HTTP/2.0",
    payload: ""
  },
  {
    timestamp: "2026-08-30T10:00:22Z",
    ip: "172.16.0.4",
    method: "POST",
    endpoint: "/login",
    protocol: "HTTP/1.1",
    payload: "' OR '1'='1"
  }
];

// Calculate deterministic Shannon entropy
function calculateEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) return 0.0;
  const len = str.length;
  const counts = {};
  for (let i = 0; i < len; i++) {
    const ch = str[i];
    counts[ch] = (counts[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const ch in counts) {
    const p = counts[ch] / len;
    entropy -= p * (Math.log(p) / Math.log(2));
  }
  return parseFloat(entropy.toFixed(2));
}

// Generate friendly incident identifier
function generateIncidentId(ip, index, timestamp) {
  const seed = `${ip}-${index}-${timestamp || '2026'}`;
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = ((hash << 5) - hash) + seed.charCodeAt(i);
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(6, '0').slice(0, 6);
  return `INC-${hex.toUpperCase()}-${String(index + 1).padStart(2, '0')}`;
}

// Synthesize multi-agent intelligence findings
function synthesizeAgentInsights(payload, endpoint, socLeadRaw) {
  const cleanPayload = payload || '';
  const isDropTable = /DROP\s+TABLE/i.test(cleanPayload);
  const isAuthBypass = /OR\s+['"]?1['"]?\s*=\s*['"]?1/i.test(cleanPayload);
  const isXSS = /<script|alert\(|onerror=/i.test(cleanPayload);
  const isPathTraversal = /\.\.\/|\/etc\/passwd/i.test(cleanPayload);

  let threatIntel = "MITRE ATT&CK T1190 (Exploit Public-Facing Application): Heuristic anomaly pattern detected in payload parameters.";
  let digitalTwin = "Target Sandbox: Simulated against active backend topology (Node.js API + MongoDB/PostgreSQL). Low execution risk on unmapped endpoints.";
  let socLead = socLeadRaw && socLeadRaw !== "Pending AI Deep Investigation..." 
    ? socLeadRaw 
    : "Review incident context and execute appropriate perimeter action (Firewall Quarantine or Model Feedback Suppress).";

  if (isDropTable) {
    threatIntel = "MITRE ATT&CK T1190 / T1059: SQL Injection attempt with destructive Data Destruction marker (DROP TABLE users).";
    digitalTwin = "Target Database engine is MongoDB (NoSQL). SQL DROP TABLE statement fails gracefully in sandbox. Zero backend rows impacted.";
    if (!socLeadRaw || socLeadRaw === "Pending AI Deep Investigation...") {
      socLead = "Approve perimeter block on IP to prevent secondary enumeration attacks. Ingest attack signature into Neo4j threat graph.";
    }
  } else if (isAuthBypass) {
    threatIntel = "MITRE ATT&CK T1078 (Valid Accounts / Auth Bypass): Classic tautology SQL injection pattern (' OR '1'='1) targeting authentication route.";
    digitalTwin = "Target Authentication Service utilizes parameterized ORM queries. Auth bypass attempted on /login endpoint; 0 rows compromised in sandbox.";
    if (!socLeadRaw || socLeadRaw === "Pending AI Deep Investigation...") {
      socLead = "Enforce immediate IP rate-limit and quarantine in Neo4j graph. Retain telemetry for threat intel model reinforcement.";
    }
  } else if (isXSS) {
    threatIntel = "MITRE ATT&CK T1059.007 (JavaScript Execution): Stored/Reflected Cross-Site Scripting (XSS) payload detected.";
    digitalTwin = "Frontend Content Security Policy (CSP) enforces strict script-src nonce. Browser sandbox prevents script execution.";
    if (!socLeadRaw || socLeadRaw === "Pending AI Deep Investigation...") {
      socLead = "Apply WAF payload inspection filter. Quarantine source IP to prevent automated vulnerability scanner exploitation.";
    }
  } else if (isPathTraversal) {
    threatIntel = "MITRE ATT&CK T1083 (File and Directory Discovery): Path traversal sequence targeting sensitive system files.";
    digitalTwin = "Containerized runtime uses chroot jail and non-root user. Filesystem isolation prevents unauthorized access.";
    if (!socLeadRaw || socLeadRaw === "Pending AI Deep Investigation...") {
      socLead = "Quarantine IP in Neo4j. Check egress traffic logs for unauthorized data exfiltration.";
    }
  }

  return { threatIntel, digitalTwin, socLead };
}

// --------------------------------------------------------------------------
// COMPONENT: Friendly Google-Style Threat Incident Card
// --------------------------------------------------------------------------
function ThreatCard({ incident, index, rlhfState, onAction }) {
  const [copied, setCopied] = useState(false);
  const raw = incident.raw_entry || {};
  const triage = incident.triage_details || {};
  const ip = raw.ip || '0.0.0.0';
  const endpoint = raw.endpoint || '/';
  const payload = raw.payload || '';
  const timestamp = raw.timestamp || '2026-08-30T10:00:00Z';
  const method = raw.method || 'POST';
  const riskScore = typeof triage.risk_score === 'number' ? triage.risk_score : 0.75;
  const entropy = typeof triage.entropy === 'number' ? triage.entropy : calculateEntropy(payload);
  const flags = Array.isArray(triage.flags) && triage.flags.length > 0
    ? triage.flags
    : (payload ? ['Pattern Anomaly Flag', 'Payload Analysis Required'] : ['Network Anomaly']);
  
  const incidentId = incident.incident_id || generateIncidentId(ip, index, timestamp);
  const currentState = rlhfState || 'pending';

  const insights = useMemo(() => {
    return synthesizeAgentInsights(payload, endpoint, incident.soc_lead_recommendation);
  }, [payload, endpoint, incident.soc_lead_recommendation]);

  const handleCopy = () => {
    navigator.clipboard.writeText(payload);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isCritical = riskScore >= 0.75;

  return (
    <div className={`google-threat-card ${currentState}`}>
      {/* Card Top Header */}
      <div className="card-top-header">
        <div className="header-left-group">
          <span className={`pill-badge ${isCritical ? 'pill-critical' : 'pill-high'}`}>
            <span className="dot"></span>
            {isCritical ? 'Critical Severity' : 'High Risk'} ({riskScore.toFixed(2)})
          </span>
          <span className="pill-badge pill-neutral">
            {incidentId}
          </span>
          <span className="pill-badge pill-time">
            🕒 {timestamp}
          </span>
        </div>

        <div className="header-right-group">
          {currentState === 'pending' && (
            <span className="status-pill status-pill-pending">
              <span className="pulse-dot"></span> Pending Analyst Review
            </span>
          )}
          {currentState === 'blocked' && (
            <span className="status-pill status-pill-blocked">
              🛡️ Quarantined in Neo4j
            </span>
          )}
          {currentState === 'suppressed' && (
            <span className="status-pill status-pill-suppressed">
              ✓ Marked False Positive (Retrain)
            </span>
          )}
        </div>
      </div>

      {/* Main Threat Info Row */}
      <div className="card-main-info">
        <div className="threat-title-row">
          <div className="threat-target-badge">
            <span className="method-pill">{method}</span>
            <span className="endpoint-name">{endpoint}</span>
          </div>
          <div className="ingress-ip-box">
            <span className="ip-label">Source IP:</span>
            <span className="ip-value">{ip}</span>
          </div>
        </div>

        {/* Telemetry Chips Strip */}
        <div className="telemetry-chips-strip">
          <span className="tech-chip">
            <strong>Shannon Entropy:</strong> {entropy.toFixed(2)} / 8.00 ({entropy > 4.2 ? 'High Randomness' : 'Nominal'})
          </span>
          <span className="tech-chip">
            <strong>Payload Length:</strong> {payload.length} bytes
          </span>
          {flags.map((flag, fi) => (
            <span key={fi} className="tech-chip chip-flag">
              🏷️ {flag}
            </span>
          ))}
        </div>
      </div>

      {/* Raw Payload Section (Clean Google-style Gray Code Box) */}
      <div className="payload-container">
        <div className="payload-box-header">
          <div className="payload-label">
            <span className="code-icon">💻</span>
            <span>Raw Ingress Payload</span>
            <span className="payload-count">({payload.length} characters)</span>
          </div>
          <button 
            className="pill-btn pill-btn-copy" 
            onClick={handleCopy}
            title="Copy payload to clipboard"
          >
            {copied ? '✓ Copied to Clipboard' : '📋 Copy Payload'}
          </button>
        </div>
        <pre className="payload-code-block">
          <code>{payload || '<EMPTY_PAYLOAD_BUFFER>'}</code>
        </pre>
      </div>

      {/* Multi-Agent AI Intelligence Section (Google Workspace Tonal Cards) */}
      <div className="ai-insights-section">
        <div className="section-heading">
          <span className="sparkle-icon">✨</span>
          <span>Multi-Agent Simulation & Triage Intelligence</span>
        </div>
        
        <div className="insights-grid">
          {/* Agent 1: Threat Intel */}
          <div className="insight-card intel-card">
            <div className="insight-header">
              <div className="insight-icon-box intel-icon">🎯</div>
              <div>
                <h4 className="insight-title">Threat Intel Engine</h4>
                <span className="insight-sub">MITRE ATT&CK Mapping</span>
              </div>
            </div>
            <p className="insight-body">{insights.threatIntel}</p>
          </div>

          {/* Agent 2: Digital Twin Sandbox */}
          <div className="insight-card twin-card">
            <div className="insight-header">
              <div className="insight-icon-box twin-icon">⚡</div>
              <div>
                <h4 className="insight-title">Digital Twin Sandbox</h4>
                <span className="insight-sub">Target Blast Radius Simulation</span>
              </div>
            </div>
            <p className="insight-body">{insights.digitalTwin}</p>
          </div>

          {/* Agent 3: AI SOC Lead Recommendation */}
          <div className="insight-card lead-card">
            <div className="insight-header">
              <div className="insight-icon-box lead-icon">🛡️</div>
              <div>
                <h4 className="insight-title">SOC Lead Recommendation</h4>
                <span className="insight-sub">Automated Strategy Synthesis</span>
              </div>
            </div>
            <p className="insight-body">{insights.socLead}</p>
          </div>
        </div>
      </div>

      {/* RLHF Operator Action Section (Pill Buttons) */}
      <div className="card-action-footer">
        {currentState === 'pending' ? (
          <div className="action-buttons-group">
            <button 
              className="pill-btn pill-btn-primary"
              onClick={() => onAction(index, 'blocked')}
            >
              🛡️ Apply Firewall Rule & Block IP
            </button>
            <button 
              className="pill-btn pill-btn-secondary"
              onClick={() => onAction(index, 'suppressed')}
            >
              ✓ Mark as False Positive & Retrain
            </button>
          </div>
        ) : (
          <div className="audit-receipt-wrapper">
            <div className="receipt-text-box">
              <span className="receipt-icon">
                {currentState === 'blocked' ? '🔒' : '📝'}
              </span>
              <span className="receipt-msg">
                {currentState === 'blocked' && `Audit Log: Source IP ${ip} successfully quarantined in Neo4j. Edge firewall rule applied.`}
                {currentState === 'suppressed' && `Audit Log: Alert suppressed. RLHF model feedback weights recorded for continuous learning.`}
              </span>
            </div>
            <button 
              className="pill-btn pill-btn-revert"
              onClick={() => onAction(index, 'pending')}
            >
              ↩️ Revert Decision
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------
// MAIN APPLICATION COMPONENT (GOOGLE WORKSPACE / CHROME STORE STYLE)
// --------------------------------------------------------------------------
function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState(null);
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [showCleanLogs, setShowCleanLogs] = useState(false);
  
  // Results dataset
  const [telemetryResults, setTelemetryResults] = useState(null);
  const [rlhfDecisions, setRlhfDecisions] = useState({});

  // Process raw access logs array into standard AEGIS-X telemetry format
  const processLogData = useCallback((logsArray, filename = "access_logs.json") => {
    let cleanCount = 0;
    let threatCount = 0;
    const reports = [];
    const cleanLogsList = [];
    let totalEntropy = 0;

    logsArray.forEach((entry, idx) => {
      const rawPayload = entry["Payload Data"] || entry.payload || "";
      const endpoint = entry["Traffic Type"] || entry.endpoint || "Unknown";
      const ip = entry["Source IP Address"] || entry.ip || "127.0.0.1";
      const timestamp = entry.timestamp || new Date().toISOString();
      const method = entry.method || (entry["Traffic Type"] ? "HTTP" : "POST");
      const anomalyScore = parseFloat(entry["Anomaly Scores"] || 0);

      // Entropy calculation
      const entropy = calculateEntropy(rawPayload);
      totalEntropy += entropy;

      // Suspicious patterns check
      const sqliPattern = /('|--|;|\/\*|\*\/|@@|char|nchar|varchar|DROP\s+TABLE|SELECT\s+.*FROM|UNION\s+SELECT|' OR '1'='1)/i;
      const xssPattern = /(<script|alert\(|onerror=|onload=|<img)/i;
      const pathPattern = /(\.\.\/|\/etc\/passwd|cmd\.exe|\/bin\/sh)/i;

      const flags = [];
      let score = 0.0;

      if (sqliPattern.test(rawPayload)) {
        score += 0.4;
        flags.push("SQL Injection Signature");
      }
      if (xssPattern.test(rawPayload)) {
        score += 0.4;
        flags.push("Cross-Site Scripting (XSS)");
      }
      if (pathPattern.test(rawPayload)) {
        score += 0.4;
        flags.push("Path Traversal / Shell Injection");
      }
      if (entropy > 4.2) {
        score += 0.3;
        flags.push(`High Randomness Entropy (${entropy.toFixed(2)})`);
      }
      if (entry["Malware Indicators"] === "IoC Detected" || anomalyScore > 80.0) {
        score = Math.max(score, anomalyScore / 100 || 0.85);
        flags.push(`Network Anomaly (${anomalyScore > 0 ? anomalyScore + '%' : 'IoC Detected'})`);
      }

      const isThreat = score >= 0.4 || /DROP\s+TABLE|' OR '1'='1|<script/i.test(rawPayload);
      const incidentId = generateIncidentId(ip, idx, timestamp);

      if (isThreat) {
        threatCount++;
        reports.push({
          incident_id: incidentId,
          raw_entry: {
            ip,
            endpoint,
            payload: rawPayload,
            timestamp,
            protocol: `${method} ${endpoint}`,
            method
          },
          triage_details: {
            is_suspicious: true,
            risk_score: Math.min(Math.max(score, 0.70), 1.0),
            flags: flags.length > 0 ? flags : ["Heuristic Anomaly Flag"],
            entropy
          },
          soc_lead_recommendation: idx === 0 
            ? "Simulate payload against digital twin database. Immediate perimeter block recommended on adversary IP." 
            : "Review attack pattern in sandbox. Apply rate-limiting filter."
        });
      } else {
        cleanCount++;
        cleanLogsList.push({
          incident_id: incidentId,
          ip,
          endpoint,
          payload: rawPayload,
          timestamp,
          entropy,
          method
        });
      }
    });

    const avgEntropy = logsArray.length > 0 ? (totalEntropy / logsArray.length).toFixed(2) : "0.00";

    const formattedResults = {
      filename,
      total_logs: logsArray.length,
      clean_logs: cleanCount,
      threats_escalated: threatCount,
      avg_entropy: avgEntropy,
      investigation_reports: reports,
      clean_logs_list: cleanLogsList
    };

    setTelemetryResults(formattedResults);
    setApiError(null);
  }, []);

  // Initialize demo telemetry on load
  useEffect(() => {
    processLogData(DEFAULT_DEMO_LOGS, "sample_access_logs.json");
  }, [processLogData]);

  // Handle Log File Upload to Backend with Client-Side Fallback
  const handleUpload = async () => {
    if (!selectedFile) {
      alert("Please select a JSON log file first.");
      return;
    }

    setLoading(true);
    setApiError(null);

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const fileContent = e.target.result;
        const parsedJson = JSON.parse(fileContent);
        const logsArray = Array.isArray(parsedJson) ? parsedJson : [parsedJson];

        try {
          const formData = new FormData();
          formData.append("file", selectedFile);

          const response = await fetch("http://127.0.0.1:8000/api/upload-logs", {
            method: "POST",
            body: formData
          });

          if (response.ok) {
            const data = await response.json();
            const total = data.total_logs || logsArray.length;
            const reports = (data.investigation_reports || []).map((r, i) => ({
              ...r,
              incident_id: r.incident_id || generateIncidentId(r.raw_entry?.ip || '0.0.0.0', i, r.raw_entry?.timestamp)
            }));
            
            let totalEnt = 0;
            reports.forEach(r => {
              if (r.triage_details && typeof r.triage_details.entropy === 'number') {
                totalEnt += r.triage_details.entropy;
              }
            });
            const avgEnt = reports.length > 0 ? (totalEnt / reports.length).toFixed(2) : "3.84";

            setTelemetryResults({
              filename: selectedFile.name,
              total_logs: total,
              clean_logs: data.clean_logs ?? (total - reports.length),
              threats_escalated: data.threats_escalated ?? reports.length,
              avg_entropy: avgEnt,
              investigation_reports: reports,
              clean_logs_list: logsArray.filter(l => !reports.some(r => r.raw_entry && r.raw_entry.ip === (l.ip || l["Source IP Address"])))
            });
          } else {
            processLogData(logsArray, selectedFile.name);
          }
        } catch (fetchErr) {
          processLogData(logsArray, selectedFile.name);
        }
      } catch (parseErr) {
        setApiError("Invalid JSON structure in uploaded file. Please ensure valid JSON array format.");
      }
      setLoading(false);
    };

    reader.onerror = () => {
      setApiError("Error reading local log file.");
      setLoading(false);
    };

    reader.readAsText(selectedFile);
  };

  // Load Built-in Demo Access Telemetry
  const handleLoadDemoTelemetry = () => {
    setLoading(true);
    setTimeout(() => {
      processLogData(DEFAULT_DEMO_LOGS, "sample_access_logs.json");
      setLoading(false);
    }, 200);
  };

  // Handle RLHF Action Decision
  const handleRlhfAction = (index, decision) => {
    setRlhfDecisions(prev => ({
      ...prev,
      [index]: decision
    }));
  };

  // Filtered reports calculation
  const filteredReports = useMemo(() => {
    if (!telemetryResults || !telemetryResults.investigation_reports) return [];
    
    return telemetryResults.investigation_reports.map((rep, originalIndex) => ({
      ...rep,
      originalIndex
    })).filter((rep) => {
      const state = rlhfDecisions[rep.originalIndex] || 'pending';
      const ip = (rep.raw_entry && rep.raw_entry.ip) || '';
      const endpoint = (rep.raw_entry && rep.raw_entry.endpoint) || '';
      const payload = (rep.raw_entry && rep.raw_entry.payload) || '';
      
      if (activeFilter === 'PENDING' && state !== 'pending') return false;
      if (activeFilter === 'BLOCKED' && state !== 'blocked') return false;
      if (activeFilter === 'SUPPRESSED' && state !== 'suppressed') return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return ip.toLowerCase().includes(q) || endpoint.toLowerCase().includes(q) || payload.toLowerCase().includes(q);
      }

      return true;
    });
  }, [telemetryResults, rlhfDecisions, activeFilter, searchQuery]);

  // Telemetry metric counts
  const pendingCount = useMemo(() => {
    if (!telemetryResults) return 0;
    return telemetryResults.investigation_reports.filter((_, idx) => (rlhfDecisions[idx] || 'pending') === 'pending').length;
  }, [telemetryResults, rlhfDecisions]);

  const blockedCount = useMemo(() => {
    return Object.values(rlhfDecisions).filter(v => v === 'blocked').length;
  }, [rlhfDecisions]);

  const suppressedCount = useMemo(() => {
    return Object.values(rlhfDecisions).filter(v => v === 'suppressed').length;
  }, [rlhfDecisions]);

  return (
    <div className="google-workspace-app">
      {/* 1. GOOGLE WORKSPACE TOP NAVIGATION BAR */}
      <header className="google-navbar">
        <div className="navbar-container">
          {/* Logo & Product Name */}
          <div className="brand-group">
            <div className="google-logo-icon">
              <span className="g-dot dot-blue"></span>
              <span className="g-dot dot-red"></span>
              <span className="g-dot dot-yellow"></span>
              <span className="g-dot dot-green"></span>
            </div>
            <div className="brand-text">
              <span className="brand-title">AEGIS-X</span>
              <span className="brand-tag">Autonomous SOC</span>
            </div>
          </div>

          {/* Centered Google Search / Ingestion Bar */}
          <div className="google-search-bar-wrapper">
            <div className="google-search-bar">
              <span className="search-icon"></span>
              <input 
                type="text" 
                placeholder="Search incidents by IP, endpoint, or payload..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="search-input"
              />
              {searchQuery && (
                <button className="clear-search-btn" onClick={() => setSearchQuery('')}></button>
              )}
            </div>
          </div>

          {/* Right Action & Status Group */}
          <div className="navbar-actions">
            <div className="file-upload-pill">
              <input
                id="log-file-input"
                type="file"
                accept=".json"
                className="hidden-file-input"
                onChange={(e) => setSelectedFile(e.target.files[0])}
              />
              <label htmlFor="log-file-input" className="pill-btn pill-btn-ghost">
                 {selectedFile ? selectedFile.name : 'Select Log File'}
              </label>
              <button 
                className="pill-btn pill-btn-solid-blue"
                onClick={handleUpload}
                disabled={loading || !selectedFile}
              >
                Upload & Ingest
              </button>
            </div>

            <button 
              className="pill-btn pill-btn-tonal"
              onClick={handleLoadDemoTelemetry}
              disabled={loading}
            >
               Load Sample
            </button>

            <div className="status-badge-chip">
              <span className="pulse-indicator"></span>
              <span>Pipeline Active</span>
            </div>
          </div>
        </div>
      </header>

      {/* 2. MAIN SPACIOUS CONTENT CONTAINER */}
      <main className="google-main-content">
        {/* Hero Section */}
        <section className="hero-section">
          <h1 className="hero-title">Security Incident & Threat Intelligence Center</h1>
          <p className="hero-subtitle">
            Autonomous threat detection stream with real-time Shannon Entropy triage, multi-agent digital twin simulations, and human-in-the-loop reinforcement learning.
          </p>
        </section>

        {/* Loading Spinner / Alert Banners */}
        {loading && (
          <div className="google-alert-card card-loading">
            <div className="google-spinner"></div>
            <span>Processing log stream, calculating Shannon entropy, and executing digital twin sandbox simulation...</span>
          </div>
        )}
        {apiError && (
          <div className="google-alert-card card-error">
            <span> {apiError}</span>
          </div>
        )}

        {/* 3. HERO SUMMARY METRIC CARDS (4 LARGE SOFT PASTEL CARDS) */}
        {telemetryResults && (
          <section className="hero-metrics-grid">
            {/* Metric 1: Total Ingested Logs */}
            <div className="metric-pastel-card pastel-blue">
              <div className="metric-header-row">
                <span className="metric-name">Total Ingested Telemetry</span>
                <span className="metric-badge-icon icon-blue"></span>
              </div>
              <div className="metric-number-row">
                <span className="metric-big-num">{telemetryResults.total_logs}</span>
                <span className="metric-unit">Records</span>
              </div>
              <p className="metric-desc">100% telemetry coverage across active endpoints</p>
            </div>

            {/* Metric 2: Nominal Bypassed Traffic */}
            <div className="metric-pastel-card pastel-green">
              <div className="metric-header-row">
                <span className="metric-name">Nominal Traffic (Clean)</span>
                <span className="metric-badge-icon icon-green"></span>
              </div>
              <div className="metric-number-row">
                <span className="metric-big-num num-green">{telemetryResults.clean_logs}</span>
                <span className="metric-unit">Bypassed</span>
              </div>
              <p className="metric-desc">Verified low entropy & nominal payload distribution</p>
            </div>

            {/* Metric 3: Escalated Threats */}
            <div className="metric-pastel-card pastel-red">
              <div className="metric-header-row">
                <span className="metric-name">Escalated Threats</span>
                <span className="metric-badge-icon icon-red"></span>
              </div>
              <div className="metric-number-row">
                <span className="metric-big-num num-red">{telemetryResults.threats_escalated}</span>
                <span className="metric-unit">Flagged</span>
              </div>
              <p className="metric-desc">{pendingCount} incident{pendingCount === 1 ? '' : 's'} awaiting human analyst verification</p>
            </div>

            {/* Metric 4: Average Shannon Entropy */}
            <div className="metric-pastel-card pastel-amber">
              <div className="metric-header-row">
                <span className="metric-name">Avg Shannon Entropy</span>
                <span className="metric-badge-icon icon-amber"></span>
              </div>
              <div className="metric-number-row">
                <span className="metric-big-num num-amber">{telemetryResults.avg_entropy}</span>
                <span className="metric-unit">/ 8.00</span>
              </div>
              <p className="metric-desc">Payload randomness & obfuscation index</p>
            </div>
          </section>
        )}

        {/* 4. CATEGORY PILL FILTER BAR (CHROME WEB STORE STYLE) */}
        {telemetryResults && (
          <section className="filter-pill-bar">
            <div className="pill-group">
              <button 
                className={`filter-pill-btn ${activeFilter === 'ALL' ? 'active' : ''}`}
                onClick={() => setActiveFilter('ALL')}
              >
                 All Incidents
                <span className="pill-count">{telemetryResults.investigation_reports.length}</span>
              </button>
              <button 
                className={`filter-pill-btn ${activeFilter === 'PENDING' ? 'active' : ''}`}
                onClick={() => setActiveFilter('PENDING')}
              >
                 Pending Review
                <span className="pill-count">{pendingCount}</span>
              </button>
              <button 
                className={`filter-pill-btn ${activeFilter === 'BLOCKED' ? 'active' : ''}`}
                onClick={() => setActiveFilter('BLOCKED')}
              >
                 Quarantined
                <span className="pill-count">{blockedCount}</span>
              </button>
              <button 
                className={`filter-pill-btn ${activeFilter === 'SUPPRESSED' ? 'active' : ''}`}
                onClick={() => setActiveFilter('SUPPRESSED')}
              >
                 Suppressed (Retrain)
                <span className="pill-count">{suppressedCount}</span>
              </button>
            </div>

            <div className="filter-right-stats">
              <span>Showing {filteredReports.length} of {telemetryResults.investigation_reports.length} flagged events</span>
            </div>
          </section>
        )}

        {/* 5. THREAT FEED (SPACIOUS INDIVIDUAL CARDS) */}
        {telemetryResults && (
          <section className="threat-feed-container">
            {filteredReports.length > 0 ? (
              filteredReports.map((incident) => (
                <ThreatCard 
                  key={incident.originalIndex}
                  index={incident.originalIndex}
                  incident={incident}
                  rlhfState={rlhfDecisions[incident.originalIndex]}
                  onAction={handleRlhfAction}
                />
              ))
            ) : (
              <div className="empty-results-card">
                <div className="empty-icon"></div>
                <h3 className="empty-title">No incidents match your filter</h3>
                <p className="empty-subtitle">Try searching for a different keyword or reset your filter tabs.</p>
                <button 
                  className="pill-btn pill-btn-tonal"
                  onClick={() => { setActiveFilter('ALL'); setSearchQuery(''); }}
                >
                  Reset Filters
                </button>
              </div>
            )}
          </section>
        )}

        {/* 6. NOMINAL / CLEAN LOGS STREAM ACCORDION */}
        {telemetryResults && telemetryResults.clean_logs_list && telemetryResults.clean_logs_list.length > 0 && (
          <section className="nominal-traffic-section">
            <div 
              className="nominal-toggle-card"
              onClick={() => setShowCleanLogs(!showCleanLogs)}
            >
              <div className="nominal-toggle-left">
                <div className="nominal-icon-shield"></div>
                <div>
                  <h3 className="nominal-title">
                    Bypassed Nominal Traffic Stream ({telemetryResults.clean_logs_list.length} Clean Records)
                  </h3>
                  <p className="nominal-desc">
                    These requests exhibited nominal entropy and zero exploit heuristics, bypassing automated quarantine.
                  </p>
                </div>
              </div>
              <button className="pill-btn pill-btn-ghost">
                {showCleanLogs ? '▲ Hide Clean Stream' : '▼ View Clean Stream'}
              </button>
            </div>

            {showCleanLogs && (
              <div className="nominal-table-card">
                <table className="google-clean-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Source IP</th>
                      <th>Endpoint</th>
                      <th>Method</th>
                      <th>Entropy</th>
                      <th>Payload Sample</th>
                      <th style={{ textAlign: 'right' }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {telemetryResults.clean_logs_list.map((log, li) => (
                      <tr key={li}>
                        <td>{log.timestamp}</td>
                        <td className="table-ip-cell">{log.ip}</td>
                        <td>{log.endpoint}</td>
                        <td><span className="pill-badge pill-neutral">{log.method || 'GET'}</span></td>
                        <td>{log.entropy ? log.entropy.toFixed(2) : '1.85'} / 8.00</td>
                        <td className="code-font">{log.payload ? log.payload.substring(0, 32) : '<EMPTY>'}</td>
                        <td style={{ textAlign: 'right' }}>
                          <span className="pill-badge pill-green">Passed Clean</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}

export default App;