# main.py

import uvicorn
import asyncio
import random
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

# Import the new simulator functions
from ai_analyst import generate_threat_report
from packet_analyzer import (
    start_sniffing, 
    start_analysis_loop, 
    anomaly_alerts_queue,
    incident_database,
    db_lock
)
from attack_simulator import simulate_port_scan, simulate_udp_flood

# 1. Initialize FastAPI App 
app = FastAPI(
    title="NetSentinel Backend",
    description="Manages packet analysis, anomaly detection, and alert streaming."
)

# 2. Data Models  
class IncidentSequenceItem(BaseModel):
    timestamp: str
    type: str
    details: str

class Alert(BaseModel):
    incident_id: str
    threat_score: int
    main_event: str
    status: str
    sequence: List[IncidentSequenceItem]
    ai_summary: str

class FullIncident(BaseModel):
    incident_id: str
    threat_score: int
    main_event: str
    status: str
    first_seen: float
    last_seen: float
    attacker_ip: str
    sequence: List[IncidentSequenceItem]
    ai_summary: Optional[str] = None

# Response model for the simulator
class SimulationResponse(BaseModel):
    message: str

# 3. Startup Event 
@app.on_event("startup")
async def startup_event():
    start_sniffing()
    start_analysis_loop()

# 4. WebSocket 
@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    await websocket.accept()
    print("Frontend client connected.")
    
    try:
        while True:
            if anomaly_alerts_queue:
                initial_alert_data = anomaly_alerts_queue.popleft()
                
                print(f"--- New Incident Detected: {initial_alert_data['incident_id']} ---")

                print(f"Generating AI report for {initial_alert_data['incident_id']}...")
                report_text = await generate_threat_report(initial_alert_data)
                print(f"AI Report: {report_text}")
                
                initial_alert_data["ai_summary"] = report_text
                with db_lock:
                    if initial_alert_data['incident_id'] in incident_database:
                        incident_database[initial_alert_data['incident_id']]['ai_summary'] = report_text
                
                alert_to_send = Alert(**initial_alert_data)
                await websocket.send_json(alert_to_send.model_dump())
                print(f"Sent NEW incident alert {alert_to_send.incident_id}")
            
            else:
                await asyncio.sleep(1)

    except WebSocketDisconnect:
        print("Frontend client disconnected.")
    except Exception as e:
        print(f"An error occurred: {e}")

# 5. Incident API 

@app.get("/api/incident/{incident_id}", response_model=FullIncident)
def get_incident_details(incident_id: str):
    print(f"Frontend requested details for {incident_id}")
    with db_lock:
        incident = incident_database.get(incident_id)
        
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return FullIncident(**incident)


# Simulator API Endpoints

@app.post("/api/simulate/portscan", response_model=SimulationResponse)
async def http_simulate_portscan():
    """
    Triggers a simulated port scan on localhost.
    This will be detected by the sniffer as a real anomaly.
    """
    simulate_port_scan()
    return {"message": "Port scan simulation started."}

@app.post("/api/simulate/udpflood", response_model=SimulationResponse)
async def http_simulate_udpflood():
    """
    Triggers a simulated UDP flood (DDoS) on localhost.
    This will be detected by the sniffer as a real anomaly.
    """
    simulate_udp_flood()
    return {"message": "UDP flood simulation started."}

# 7. Root Endpoint 
@app.get("/")
def read_root():
    return {"status": "NetSentinel Backend is running."}

# 8. Run the Server 
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)