# ids_app.py
import joblib
import streamlit as st
import pandas as pd
import numpy as np
import xgboost as xgb
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import os
import datetime
import json

# Load the pre-trained model
model = xgb.Booster()
model.load_model("ARTIFACTS/xgb_model.json")
scaler = joblib.load('ARTIFACTS/scaler.pkl')
label = joblib.load("ARTIFACTS/label_encoder_after_preprocessing.pkl")

# Create logs directory if it doesn't exist
if not os.path.exists("logs"):
    os.makedirs("logs")

# Placeholder for flow data
flows = defaultdict(lambda: {
    'packets': [], 'timestamps': [], 'fwd_sizes': [], 'bwd_sizes': [],
    'start_time': time.time(), 'fwd_first_win': None, 'bwd_first_win': None
})

# Feature list (same as training)
feature_names = ['destination_port', 'init_win_bytes_backward', 'min_seg_size_forward',
       'total_length_of_bwd_packets', 'init_win_bytes_forward',
       'max_packet_length', 'fwd_packet_length_max', 'flow_iat_mean',
       'flow_iat_max', 'bwd_packets/s', 'flow_packets/s', 'fwd_iat_min',
       'avg_bwd_segment_size', 'total_length_of_fwd_packets', 'flow_iat_std',
       'average_packet_size', 'bwd_packet_length_min', 'fwd_iat_std',
       'bwd_packet_length_max', 'flow_bytes/s']

# Setup logging functions
def get_log_filename():
    """Generate a timestamped log filename"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"logs/network_activity_{timestamp}.log"

def log_packet(logfile, pkt, message=""):
    """Log a packet to the specified log file"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    log_entry = {
        "timestamp": timestamp,
        "message": message
    }
    
    if IP in pkt:
        log_entry["src_ip"] = pkt[IP].src
        log_entry["dst_ip"] = pkt[IP].dst
        log_entry["proto"] = pkt[IP].proto
        
        if TCP in pkt:
            log_entry["protocol"] = "TCP"
            log_entry["sport"] = pkt[TCP].sport
            log_entry["dport"] = pkt[TCP].dport
            log_entry["flags"] = str(pkt[TCP].flags)
        elif UDP in pkt:
            log_entry["protocol"] = "UDP"
            log_entry["sport"] = pkt[UDP].sport
            log_entry["dport"] = pkt[UDP].dport
        
        log_entry["length"] = len(pkt)
    
    with open(logfile, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def log_flow_results(logfile, flow_results):
    """Log flow analysis results to the specified log file"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    with open(logfile, "a") as f:
        f.write(f"\n===== FLOW ANALYSIS RESULTS at {timestamp} =====\n")
        for result in flow_results:
            f.write(f"Flow: {result['src']}:{result['sport']} -> {result['dst']}:{result['dport']} ({result['protocol']})\n")
            f.write(f"Prediction: {result['prediction']}\n")
            f.write("Key metrics:\n")
            for feature in ['flow_packets/s', 'flow_bytes/s', 'average_packet_size', 'max_packet_length']:
                f.write(f"  - {feature}: {result[feature]:.2f}\n")
            f.write("---\n")
        f.write("======================================\n\n")

def extract_features(flow):
    duration = time.time() - flow['start_time']
    if duration == 0: duration = 1e-6  # avoid divide by zero

    fwd_sizes = flow['fwd_sizes']
    bwd_sizes = flow['bwd_sizes']
    timestamps = flow['timestamps']
    packets = flow['packets']
    all_sizes = fwd_sizes + bwd_sizes

    return {
        'destination_port': packets[-1].dport if hasattr(packets[-1], 'dport') else 0,
        'init_win_bytes_backward': flow['bwd_first_win'] or 0,
        'min_seg_size_forward': min(fwd_sizes) if fwd_sizes else 0,
        'total_length_of_bwd_packets': sum(bwd_sizes),
        'init_win_bytes_forward': flow['fwd_first_win'] or 0,
        'max_packet_length': max(all_sizes) if all_sizes else 0,
        'fwd_packet_length_max': max(fwd_sizes) if fwd_sizes else 0,
        'flow_iat_mean': np.mean(np.diff(timestamps)) if len(timestamps) > 1 else 0,
        'flow_iat_max': max(np.diff(timestamps)) if len(timestamps) > 1 else 0,
        'bwd_packets/s': len(bwd_sizes) / duration,
        'flow_packets/s': len(packets) / duration,
        'fwd_iat_min': min(np.diff([t for i, t in enumerate(timestamps) if i < len(fwd_sizes)])) if len(fwd_sizes) > 1 else 0,
        'avg_bwd_segment_size': np.mean(bwd_sizes) if bwd_sizes else 0,
        'total_length_of_fwd_packets': sum(fwd_sizes),
        'flow_iat_std': np.std(np.diff(timestamps)) if len(timestamps) > 1 else 0,
        'average_packet_size': np.mean(all_sizes) if all_sizes else 0,
        'bwd_packet_length_min': min(bwd_sizes) if bwd_sizes else 0,
        'fwd_iat_std': np.std(np.diff([t for i, t in enumerate(timestamps) if i < len(fwd_sizes)])) if len(fwd_sizes) > 1 else 0,
        'bwd_packet_length_max': max(bwd_sizes) if bwd_sizes else 0,
        'flow_bytes/s': sum(all_sizes) / duration
    }

def packet_handler(pkt, logfile):
    if not IP in pkt or not (TCP in pkt or UDP in pkt): return
    proto = "TCP" if TCP in pkt else "UDP"
    ip = pkt[IP]
    sport, dport = pkt.sport, pkt.dport
    fid = (ip.src, ip.dst, sport, dport, proto)
    
    # Log the packet
    log_message = f"Captured {proto} packet: {ip.src}:{sport} -> {ip.dst}:{dport}"
    log_packet(logfile, pkt, log_message)

    flow = flows[fid]
    flow['packets'].append(pkt)
    flow['timestamps'].append(time.time())

    size = len(pkt)
    if ip.src < ip.dst:  # forward
        flow['fwd_sizes'].append(size)
        if TCP in pkt and flow['fwd_first_win'] is None:
            flow['fwd_first_win'] = pkt[TCP].window
    else:  # backward
        flow['bwd_sizes'].append(size)
        if TCP in pkt and flow['bwd_first_win'] is None:
            flow['bwd_first_win'] = pkt[TCP].window

# Streamlit UI
st.title("Real-Time Network Intrusion Detection System")

# Log file settings
st.sidebar.header("Logging Settings")
log_enabled = st.sidebar.checkbox("Enable Logging", value=True)
if log_enabled:
    log_filename = get_log_filename()
    st.sidebar.info(f"Log file: {log_filename}")
    
    # Create empty log file with header
    with open(log_filename, "w") as f:
        f.write(f"# Network Activity Log - Started {datetime.datetime.now()}\n")
        f.write("# JSON format: one entry per line\n\n")

# Sniffing options
st.sidebar.header("Sniffing Settings")
packet_count = st.sidebar.slider("Number of packets to capture", 10, 500, 50)
sniff_timeout = st.sidebar.slider("Sniffing timeout (seconds)", 5, 60, 10)

if st.button("Start Sniffing"):
    if log_enabled:
        st.info(f"Sniffing started... Logging to {log_filename}")
    else:
        st.info("Sniffing started... (Logging disabled)")
    
    # Clear previous flows
    flows.clear()
    
    # Create a wrapper function to use in sniff
    def sniff_wrapper(pkt):
        if log_enabled:
            return packet_handler(pkt, log_filename)
        else:
            return packet_handler(pkt, None)
    
    # Start sniffing
    with st.spinner(f"Capturing packets (max {packet_count} or {sniff_timeout}s timeout)..."):
        sniff(count=packet_count, prn=sniff_wrapper, timeout=sniff_timeout)

    # Process and display results
    records = []
    for fid, flow in flows.items():
        if len(flow['packets']) < 2:  # Skip flows with too few packets
            continue
            
        features = extract_features(flow)
        df = pd.DataFrame([features])[feature_names]
        dtest = xgb.DMatrix(df.values, feature_names=feature_names)
        pred = model.predict(dtest)
        
        record = {
            'src': fid[0],
            'dst': fid[1],
            'sport': fid[2],
            'dport': fid[3],
            'protocol': fid[4],
            'prediction': label.inverse_transform([int(pred[0])])[0],
            'packets_captured': len(flow['packets']),
            **features
        }
        records.append(record)

    # Display results
    if records:
        result_df = pd.DataFrame(records)
        
        # Highlight suspicious traffic
        def highlight_suspicious(s):
            is_suspicious = s['prediction'] != 0
            return ['background-color: #ffcccc' if is_suspicious else '' for _ in s]
        
        st.subheader("Analysis Results")
        st.dataframe(result_df.style.apply(highlight_suspicious, axis=1))
        
        # Log the results
        if log_enabled:
            log_flow_results(log_filename, records)
            
            # Save full results as CSV for reference
            csv_filename = log_filename.replace('.log', '.csv')
            result_df.to_csv(csv_filename, index=False)
            st.success(f"Results saved to {csv_filename}")
            
        # Summary statistics
        benign_count = sum(1 for r in records if r['prediction'] == 0)
        suspicious_count = len(records) - benign_count
        
        st.subheader("Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Flows", len(records))
        col2.metric("Benign Flows", benign_count)
        col3.metric("Suspicious Flows", suspicious_count)
        
        if suspicious_count > 0:
            st.warning(f"⚠️ Detected {suspicious_count} suspicious network flows!")
    else:
        st.warning("No flows detected. Try increasing the packet count or timeout.")

    st.success("Sniffing & Prediction complete.")

# Show log files
if st.sidebar.checkbox("Show Available Log Files"):
    log_files = [f for f in os.listdir("logs") if f.endswith('.log')]
    if log_files:
        selected_log = st.sidebar.selectbox("Select log file to view", log_files)
        if st.sidebar.button("View Selected Log"):
            with open(os.path.join("logs", selected_log), "r") as f:
                log_content = f.read()
            st.text_area("Log Content", log_content, height=400)
    else:
        st.sidebar.info("No log files found.")