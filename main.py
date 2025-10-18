# main.py

import uvicorn
import asyncio
import random
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from ai_analyst import generate_threat_report

# 1. Initialize FastAPI App 
app = FastAPI(
    title="NetSentinel Backend",
    description="Manages packet analysis, anomaly detection, and alert streaming."
)

# 2. Data Models (SEE This with Person B & C) 
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
    ai_summary: str  # This will hold the GenAI report

# 3. Mock WebSocket Endpoint
@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    await websocket.accept()
    print("Frontend client connected.")
    
    try:
        while True:
            await asyncio.sleep(5) # Wait 5 seconds

            # 1. Generate Fake Alert Data
            incident_id = f"INC-{random.randint(100, 999)}"
            score = random.randint(75, 99)
            
            # This is the raw data our system "detects"
            alert_data = {
                "incident_id": incident_id,
                "threat_score": score,
                "main_event": "Potential Data Exfiltration",
                "status": "new",
                "sequence": [
                    IncidentSequenceItem(
                        timestamp=datetime.now().isoformat(),
                        type="Port Scan",
                        details=f"Attacker {random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)} scanned ports 1-1024."
                    ).model_dump(),
                    IncidentSequenceItem(
                        timestamp=datetime.now().isoformat(),
                        type="Connection Attempt",
                        details="Attacker attempted RDP connection on port 3389."
                    ).model_dump(),
                    IncidentSequenceItem(
                        timestamp=datetime.now().isoformat(),
                        type="Data Outflow",
                        details="Small but steady 5MB/min outbound traffic detected."
                    ).model_dump()
                ]
            }

            # 2. NEW: Call the AI Analyst 
            print(f"Generating AI report for {incident_id}...")
            report_text = await generate_threat_report(alert_data)
            print(f"AI Report: {report_text}")
            
            # 3. NEW: Add the AI report to our data 
            alert_data["ai_summary"] = report_text
            
            # 4. Validate and send the full enriched alert 
            full_alert = Alert(**alert_data)
            await websocket.send_json(full_alert.model_dump())
            print(f"Sent enriched mock alert {incident_id}")

    except WebSocketDisconnect:
        print("Frontend client disconnected.")
    except Exception as e:
        print(f"An error occurred: {e}")

# 4. Root Endpoint for Testing 
@app.get("/")
def read_root():
    return {"status": "NetSentinel Backend is running."}

# 5. Run the Server (for development) 
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)