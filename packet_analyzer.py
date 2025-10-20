# packet_analyzer.py

import time
import pandas as pd
import random
import os.path  
import joblib   
from collections import deque
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from threading import Thread, Lock
from datetime import datetime

# Configuration 
TRAINING_PACKET_COUNT = 500
MAX_PACKET_QUEUE_SIZE = 2000
ANALYSIS_WINDOW_SECONDS = 10
INCIDENT_COOLDOWN_SECONDS = 300
MODEL_FILE_PATH = "netsentinel_model.joblib"  # <-- NEW: Model save path

# Global State 
packet_queue = deque(maxlen=MAX_PACKET_QUEUE_SIZE)
queue_lock = Lock()

model = IsolationForest(contamination=0.01)
is_model_trained = False
last_analysis_time = time.time()

incident_database = {} 
active_ip_to_incident = {} 
db_lock = Lock()
ip_lookup_lock = Lock()

anomaly_alerts_queue = deque() 

# (packet_callback and start_sniffing)
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

# 2. Anomaly Detection 

def try_load_model():
    """
    Attempts to load the pre-trained model from disk.
    Returns True on success, False on failure.
    """
    global model, is_model_trained
    if os.path.exists(MODEL_FILE_PATH):
        try:
            print(f"[Analyzer] Found existing model '{MODEL_FILE_PATH}'. Loading...")
            model = joblib.load(MODEL_FILE_PATH)
            is_model_trained = True
            print("[Analyzer] Model loaded successfully. Switching to detection mode.")
            return True
        except Exception as e:
            print(f"[Analyzer] Error loading model: {e}. Will retrain.")
            return False
    else:
        print("[Analyzer] No model file found. Will train a new one.")
        return False

def analyze_traffic():
    """
    Main analysis loop.
    Loads or trains model, then continuously analyzes traffic.
    """
    global is_model_trained, last_analysis_time, model
    
    print("[Analyzer] Traffic analyzer started.")
    
    # Try to load model first
    if try_load_model():
        # Success! Clear the queue and skip to the detection loop.
        with queue_lock:
            packet_queue.clear()

    while True:
        # Training Block 
        if not is_model_trained:
            with queue_lock:
                current_packets = list(packet_queue)
            
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
                
                # Save the trained model
                try:
                    print(f"[Analyzer] Saving trained model to '{MODEL_FILE_PATH}'...")
                    joblib.dump(model, MODEL_FILE_PATH)
                    print("[Analyzer] Model saved.")
                except Exception as e:
                    print(f"[Analyzer] Error saving model: {e}")
                
                print("[Analyzer] Model training complete. Switching to detection mode.")
                with queue_lock:
                    packet_queue.clear()
                continue
        
        # Anomaly Detection Block 
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
        
        if anomaly_indices:
            print(f"[Analyzer] !!! Found {len(anomaly_indices)} anomalous packets !!!")
            
            for index in anomaly_indices:
                anomaly_packet = packets_to_analyze[index]
                attacker_ip = anomaly_packet['src_ip']
                
                event_data = {
                    "timestamp": datetime.fromtimestamp(anomaly_packet['timestamp']).isoformat(),
                    "type": "Anomalous Packet",
                    "details": f"Packet from {attacker_ip}:{anomaly_packet['src_port']} to {anomaly_packet['dst_ip']}:{anomaly_packet['dst_port']} (Proto: {anomaly_packet['proto']}, Size: {anomaly_packet['pkt_len']})"
                }
                
                with ip_lookup_lock, db_lock:
                    if attacker_ip in active_ip_to_incident:
                        incident_id, last_seen = active_ip_to_incident[attacker_ip]
                        
                        if time.time() - last_seen < INCIDENT_COOLDOWN_SECONDS:
                            print(f"[Analyzer] Correlating event with existing incident {incident_id}")
                            incident_database[incident_id]['sequence'].append(event_data)
                            incident_database[incident_id]['threat_score'] = min(100, incident_database[incident_id]['threat_score'] + 5)
                            incident_database[incident_id]['last_seen'] = time.time()
                            active_ip_to_incident[attacker_ip] = (incident_id, time.time())
                        else:
                            print(f"[Analyzer] Cooldown expired for {attacker_ip}. Creating new incident.")
                            create_new_incident(attacker_ip, event_data)
                    else:
                        print(f"[Analyzer] New attacker IP {attacker_ip}. Creating new incident.")
                        create_new_incident(attacker_ip, event_data)


def create_new_incident(attacker_ip, first_event):
    incident_id = f"INC-REAL-{random.randint(1000, 9999)}"
    current_time = time.time()
    
    new_incident = {
        "incident_id": incident_id,
        "threat_score": 90,
        "main_event": "ML Anomaly Detected",
        "status": "new",
        "first_seen": current_time,
        "last_seen": current_time,
        "attacker_ip": attacker_ip,
        "sequence": [first_event]
    }
    
    incident_database[incident_id] = new_incident
    active_ip_to_incident[attacker_ip] = (incident_id, current_time)
    
    initial_alert_data = {
        "incident_id": incident_id,
        "threat_score": new_incident['threat_score'],
        "main_event": new_incident['main_event'],
        "status": new_incident['status'],
        "sequence": [first_event]
    }
    
    anomaly_alerts_queue.append(initial_alert_data)

def start_analysis_loop():
    t = Thread(target=analyze_traffic, daemon=True)
    t.start()