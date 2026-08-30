import os
import json
from crewai import Agent, Task, Crew, Process, LLM
from crewai_tools import SerperDevTool

# Set your Search API Key here
os.environ["SERPER_API_KEY"] = "Your_Serper_api_key"

# Initialize the Tool
search_tool = SerperDevTool()

# Connect CrewAI to your local Ollama Engine
local_llm = LLM(
    model="ollama/llama3.2:3b",
    base_url="http://localhost:11434",
    temperature=0.2, 
)

# --- Define the Agents ---

threat_intel_agent = Agent(
    role='Threat Intelligence Specialist',
    goal='Identify if a web payload is a known MITRE technique or a novel Zero-Day attack by searching the internet.',
    backstory='You are a senior SOC analyst with deep knowledge of the MITRE ATT&CK framework. If a payload looks unfamiliar, you search the web for recent CVEs, security blog posts, and live zero-day threat intelligence.',
    llm=local_llm,
    tools=[search_tool], # <--- SERP API Tool Added Here!
    verbose=True,
    allow_delegation=False
)

digital_twin_agent = Agent(
    role='Digital Twin Simulator',
    goal='Simulate the execution of a malicious payload and predict its blast radius (impact).',
    backstory='You are a secure sandbox environment. You safely evaluate what a piece of malicious code would do if executed on a live database or server.',
    llm=local_llm,
    verbose=True,
    allow_delegation=False
)

soc_lead_agent = Agent(
    role='SOC Lead Analyst',
    goal='Compile threat intelligence and simulation data into a final recommendation for the human analyst.',
    backstory='You manage the SOC team. You ensure that business continuity is maintained while keeping the system secure.',
    llm=local_llm,
    verbose=True,
    allow_delegation=False
)

# --- Define the Workflow Function ---
def run_investigation_pipeline(payload: str, endpoint: str):
    
    intel_task = Task(
        description=f"Analyze this suspicious payload: '{payload}' targeting the '{endpoint}' endpoint. Search the internet to find if this is a known zero-day attack or maps to a MITRE technique.",
        expected_output="A short paragraph identifying the attack type, its MITRE technique name, or recent CVE zero-day context from the web.",
        agent=threat_intel_agent,
    )

    simulation_task = Task(
        description=f"Simulate the execution of this payload: '{payload}'. Assume the backend is a Node.js API with a MongoDB database. What is the exact blast radius?",
        expected_output="A short, direct prediction of the blast radius and system impact.",
        agent=digital_twin_agent,
    )

    recommendation_task = Task(
        description="Review the threat intelligence and the simulation impact. Provide a final, concise recommendation on whether to block the IP or flag it for human review.",
        expected_output="A 2-3 sentence final recommendation for the human analyst.",
        agent=soc_lead_agent,
        context=[intel_task, simulation_task]
    )

    soc_crew = Crew(
        agents=[threat_intel_agent, digital_twin_agent, soc_lead_agent],
        tasks=[intel_task, simulation_task, recommendation_task],
        process=Process.sequential,
        verbose=True
    )

    return soc_crew.kickoff()
