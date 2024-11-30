# Moxie Network Analyzer

A tool for Moxie robot owners to analyze and capture network traffic patterns for maintaining robot functionality after server shutdown.

## Features

- Captures HTTPS/WSS traffic between Moxie and servers
- Identifies API endpoints and communication patterns
- Logs WebSocket messages and connection data
- Generates detailed analysis reports
- User-friendly GUI interface
- Cross-platform support

## Installation

### Prerequisites
```bash
pip install PyQt5 pyshark scapy cryptography
```

### Windows
1. Download `MoxieAnalyzer.exe` from releases
2. https://drive.google.com/file/d/1Yk33jotR3q6JsmcRbmPUI_c3mh7RDIA1/view?usp=sharing
3. Install Npcap from [npcap.org](https://npcap.org)
4. Run executable

### Linux/MacOS
1. Clone repository
2. Install dependencies:
```bash
sudo apt-get install libpcap-dev python3-dev # Linux
brew install libpcap # MacOS
```
3. Run `python3 moxie_analyzer.py`

## Usage

1. Launch application
2. Select network interface (usually "WiFi" or "wlan0")
3. Click "Start Capture"
4. Power on Moxie robot
5. Let capture run for 10-15 minutes during normal Moxie operation
6. Click "Stop Capture"

Analysis files will be saved in `moxie_data_[timestamp]` directory.

## Output Files

- `captured_traffic.json`: Raw packet data
- `analysis_report.json`: Endpoint and pattern analysis
- `api_calls.json`: Detected API endpoints
- `patterns.json`: Communication patterns

## Legal Notice

This tool is for personal use only. Users are responsible for compliance with applicable laws and terms of service.

## Contributing

1. Fork repository
2. Create feature branch
3. Submit pull request

## Support

- Submit issues via GitHub
- Join discussion in [Moxie TikTokk]()
- Email me your Logs! I need your [`moxie_data_[timestamp]`] (mailto:mark.varkevisser@execs.com) 

## Building from Source

```bash
# Create executable
pyinstaller --onefile --windowed moxie_analyzer.py
```

## License

MIT License - See LICENSE file
