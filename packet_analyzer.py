# packet_analyzer.py

import time
import pandas as pd
import random
from collections import deque
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from threading import Thread, Lock
from datetime import datetime

# Configuration 
TRAINING_PACKET_COUNT = 500
MAX_PACKET_QUEUE_SIZE = 2000
ANALYSIS_WINDOW_SECONDS = 10
# How long to track an attacker's IP before creating a new incident 
INCIDENT_COOLDOWN_SECONDS = 300 # 5 minutes

# Global State 
packet_queue = deque(maxlen=MAX_PACKET_QUEUE_SIZE)
queue_lock = Lock()

model = IsolationForest(contamination=0.01)
is_model_trained = False
last_analysis_time = time.time()

# This queue still just sends the initial alert
anomaly_alerts_queue = deque() 

# Correlation Database
# This holds the full "story" for every incident
incident_database = {} 
# This is a lookup to find an active incident by attacker IP
active_ip_to_incident = {} 
# We need locks for our new global dicts
db_lock = Lock()
ip_lookup_lock = Lock()


# 1. Packet Sniffing (Scapy)
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        pkt_len = packet[IP].len
        
        src_port, dst_port = 0, 0
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        features = {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "pkt_len": pkt_len
        }
        
        with queue_lock:
            packet_queue.append(features)

def start_sniffing():
    print("[Analyzer] Starting packet sniffer...")
    t = Thread(target=lambda: sniff(prn=packet_callback, store=0), daemon=True)
    t.start()

# 2. Anomaly Detection (Scikit-learn)

def analyze_traffic():
    global is_model_trained, last_analysis_time, model
    
    print("[Analyzer] Traffic analyzer started.")
    
    while True:
        with queue_lock:
            current_packets = list(packet_queue)
        
        if not is_model_trained:
            if len(current_packets) < TRAINING_PACKET_COUNT:
                print(f"[Analyzer] Collecting training data... {len(current_packets)}/{TRAINING_PACKET_COUNT} packets.")
                time.sleep(2)
                continue
            else:
                print("[Analyzer] Training Isolation Forest model...")
                df = pd.DataFrame(current_packets)
                features_to_train = df[['proto', 'src_port', 'dst_port', 'pkt_len']]
                model.fit(features_to_train)
                is_model_trained = True
                print("[Analyzer] Model training complete. Switching to detection mode.")
                with queue_lock:
                    packet_queue.clear()
                continue
       
        current_time = time.time()
        if current_time - last_analysis_time < ANALYSIS_WINDOW_SECONDS:
            time.sleep(1)
            continue
        
        last_analysis_time = current_time
        
        packets_to_analyze = []
        with queue_lock:
            while packet_queue:
                packets_to_analyze.append(packet_queue.popleft())
        
        if not packets_to_analyze:
            continue
        
        df = pd.DataFrame(packets_to_analyze)
        print(f"[Analyzer] Analyzing {len(df)} packets from last ~{ANALYSIS_WINDOW_SECONDS}s...")
        
        features_to_predict = df[['proto', 'src_port', 'dst_port', 'pkt_len']]
        scores = model.predict(features_to_predict)
        
        anomaly_indices = [i for i, score in enumerate(scores) if score == -1]
        
        # Process anomalies with new correlation logic 
        if anomaly_indices:
            print(f"[Analyzer] !!! Found {len(anomaly_indices)} anomalous packets !!!")
            
            for index in anomaly_indices:
                anomaly_packet = packets_to_analyze[index]
                
                # We'll use the source IP as the "attacker" key
                attacker_ip = anomaly_packet['src_ip']
                
                # Create the "story" item for this specific event
                event_data = {
                    "timestamp": datetime.fromtimestamp(anomaly_packet['timestamp']).isoformat(),
                    "type": "Anomalous Packet",
                    "details": f"Packet from {attacker_ip}:{anomaly_packet['src_port']} to {anomaly_packet['dst_ip']}:{anomaly_packet['dst_port']} (Proto: {anomaly_packet['proto']}, Size: {anomaly_packet['pkt_len']})"
                }
                
                # Now, let's correlate this event
                with ip_lookup_lock, db_lock:
                    
                    # Check if this IP is already part of an active incident
                    if attacker_ip in active_ip_to_incident:
                        incident_id, last_seen = active_ip_to_incident[attacker_ip]
                        
                        # Check if it's within the cooldown window
                        if time.time() - last_seen < INCIDENT_COOLDOWN_SECONDS:
                            # EXISTING INCIDENT
                            print(f"[Analyzer] Correlating event with existing incident {incident_id}")
                            
                            # Add this event to the story
                            incident_database[incident_id]['sequence'].append(event_data)
                            # Update the incident's threat score and timestamp
                            incident_database[incident_id]['threat_score'] = min(100, incident_database[incident_id]['threat_score'] + 5)
                            incident_database[incident_id]['last_seen'] = time.time()
                            
                            # Update the IP lookup timestamp
                            active_ip_to_incident[attacker_ip] = (incident_id, time.time())
                            
                            # We DON'T send a new WebSocket alert. The frontend already knows.
                            
                        else:
                            # COOLDOWN EXPIRED, NEW INCIDENT 
                            print(f"[Analyzer] Cooldown expired for {attacker_ip}. Creating new incident.")
                            create_new_incident(attacker_ip, event_data)
                    
                    else:
                        print(f"[Analyzer] New attacker IP {attacker_ip}. Creating new incident.")
                        create_new_incident(attacker_ip, event_data)

# Helper function to create new incidents 
def create_new_incident(attacker_ip, first_event):
    """
    Handles the logic for creating a new incident entry.
    This MUST be called from within the locked block.
    """
    incident_id = f"INC-REAL-{random.randint(1000, 9999)}"
    current_time = time.time()
    
    # This is the full incident data
    new_incident = {
        "incident_id": incident_id,
        "threat_score": 90, # Start high
        "main_event": "ML Anomaly Detected",
        "status": "new",
        "first_seen": current_time,
        "last_seen": current_time,
        "attacker_ip": attacker_ip,
        "sequence": [first_event] # Add the first event
        # ai_summary will be added in main.py
    }
    
    # Add to our databases
    incident_database[incident_id] = new_incident
    active_ip_to_incident[attacker_ip] = (incident_id, current_time)
    
    # This is the initial alert we send to the frontend.
    # Note: We send a copy, without the full sequence to keep it light.
    initial_alert_data = {
        "incident_id": incident_id,
        "threat_score": new_incident['threat_score'],
        "main_event": new_incident['main_event'],
        "status": new_incident['status'],
        "sequence": [first_event] # Send just the first event as a preview
    }
    
    # Add to the WebSocket queue
    anomaly_alerts_queue.append(initial_alert_data)

def start_analysis_loop():
    t = Thread(target=analyze_traffic, daemon=True)
    t.start()