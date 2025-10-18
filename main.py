# main.py

import uvicorn
import asyncio
import random
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

# Import the AI Analyst AND Packet Analyzer 
from ai_analyst import generate_threat_report
from packet_analyzer import start_sniffing, start_analysis_loop, anomaly_alerts_queue

# 1. Initialize FastAPI App 
app = FastAPI(
    title="NetSentinel Backend",
    description="Manages packet analysis, anomaly detection, and alert streaming."
)

# 2. Data Models (Same as before) 
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

# 3. NEW: Add startup event 
@app.on_event("startup")
async def startup_event():
    """
    On server startup, start the background tasks.
    """
    start_sniffing()        # Start Scapy
    start_analysis_loop()   # Start the ML analyzer

# 4. WebSocket 
@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    await websocket.accept()
    print("Frontend client connected.")
    
    try:
        while True:
            # Check for REAL alerts 
            if anomaly_alerts_queue:
                # We have a real anomaly!
                raw_alert_data = anomaly_alerts_queue.popleft()
                
                print(f"--- Real Anomaly Detected: {raw_alert_data['incident_id']} ---")

                # 2. Call the AI Analyst (Same as before) 
                print(f"Generating AI report for {raw_alert_data['incident_id']}...")
                report_text = await generate_threat_report(raw_alert_data)
                print(f"AI Report: {report_text}")
                
                # 3. Add the AI report to our data 
                raw_alert_data["ai_summary"] = report_text
                
                # 4. Validate and send the full enriched alert 
                full_alert = Alert(**raw_alert_data)
                await websocket.send_json(full_alert.model_dump())
                print(f"Sent enriched REAL alert {raw_alert_data['incident_id']}")
            
            else:
                # No anomaly, just wait
                await asyncio.sleep(1) # Check the queue every second

    except WebSocketDisconnect:
        print("Frontend client disconnected.")
    except Exception as e:
        print(f"An error occurred: {e}")

# 5. Root Endpoint 
@app.get("/")
def read_root():
    return {"status": "NetSentinel Backend is running."}

# 6. Run the Server  
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)