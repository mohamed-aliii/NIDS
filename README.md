# Network Intrusion Detection System (NIDS)

A real-time network intrusion detection system that uses machine learning to identify suspicious network traffic patterns. The system captures live network packets, extracts relevant features, and classifies them as normal or malicious using a pre-trained XGBoost model.

## Features

- Real-time packet capture and analysis
- Machine learning-based intrusion detection
- Interactive Streamlit-based web interface
- Detailed traffic analysis and visualization
- Logging of suspicious activities
- Model retraining capabilities

## Prerequisites

- Python 3.8+
- Npcap (Windows) or libpcap (Linux/macOS)
- Administrative/root privileges for packet capture

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd SECFINALPRO
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install Npcap (Windows) or libpcap (Linux/macOS)
   - Windows: Download and install Npcap from https://nmap.org/npcap/
     - Make sure to enable "WinPcap Compatibility Mode" during installation

## Usage

1. Run the application:
   ```bash
   streamlit run appz.py
   ```

2. Open the provided URL in your web browser (typically http://localhost:8501)

3. In the application:
   - Select a network interface for packet capture
   - Click "Start Sniffing" to begin monitoring
   - View real-time analysis and alerts in the dashboard

## Project Structure

```
SECFINALPRO/
├── ARTIFACTS/               # Pre-trained models and encoders
│   ├── xgb_model.pkl        # XGBoost model
│   ├── scaler.pkl          # Feature scaler
│   └── label_encoder.pkl    # Label encoder
├── Notebooks/               # Jupyter notebooks for model development
│   └── xgboost_ready.ipynb  # Model training notebook
├── logs/                    # Log files of network activity
├── appz.py                  # Main application file
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Model Training

The XGBoost model was trained on the CIC-IDS2017 dataset, which contains various types of network attacks. The model is pre-trained and ready to use, but you can retrain it using the provided Jupyter notebook:

1. Open `Notebooks/xgboost_ready.ipynb`
2. Follow the instructions to preprocess your data and train a new model
3. Save the trained model and update the paths in `appz.py`

## Troubleshooting

### Common Issues

1. **No network interfaces found**
   - Ensure Npcap is installed with WinPcap compatibility mode
   - Run the application as Administrator

2. **Permission denied errors**
   - On Linux/macOS, run with sudo: `sudo streamlit run appz.py`
   - On Windows, run Command Prompt as Administrator

3. **Dependency issues**
   - Make sure all packages in `requirements.txt` are installed
   - Consider using a virtual environment

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- CIC-IDS2017 dataset
- XGBoost library
- Scapy for packet manipulation
- Streamlit for the web interface
