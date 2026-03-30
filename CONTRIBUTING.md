# Contributing to Veil Protocol

Thank you for your interest in contributing! Veil is a community-driven project and we welcome contributions of all kinds.

## How to Help

### 1. Test Against Real DPI (Most Needed!)
If you have a VPS in a country with internet censorship, test Veil and report results.

Create an issue with: Country/ISP, DPI system (if known), transport used, morph profile used, result.

### 2. Create Traffic Morph Profiles
Capture real application traffic and create new morph profiles.

### 3. Add New Transports
Implement the transport.Transport interface for QUIC, DNS-over-HTTPS, or other protocols.

### 4. Security Audit
Review the cryptographic implementation in crypto/ package.

### 5. Bug Reports
Open an issue with steps to reproduce.

---

## Quick Start for Developers

```bash
git clone https://github.com/CYHTm/veil-core.git
cd veil-core
go test ./...      # Run all tests (394+)
go build ./...     # Build everything
go vet ./...       # Lint
```

## Code Style

- **Comments in code:** English only
- **Before commit:** always run go vet ./...
- **New features:** must include tests
- **Commit format:** type: description (feat, fix, test, docs, refactor, ci)

---

## Tutorial: Set Up a Veil Server in 5 Minutes

### Prerequisites
- A VPS with a public IP (any Linux distro)
- Go 1.21+ or pre-built binaries from Releases

### Option A: One-Command Install

```bash
curl -fsSL https://raw.githubusercontent.com/CYHTm/veil-core/main/install/server.sh | bash
```

### Option B: Manual Setup

**Step 1:** Download binary:
```bash
wget https://github.com/CYHTm/veil-core/releases/latest/download/veil-server-linux-amd64
chmod +x veil-server-linux-amd64
sudo mv veil-server-linux-amd64 /usr/local/bin/veil-server
```

**Step 2:** Generate a secret:
```bash
SECRET=zVsSfGMPB4VoYGjL1gI3To/ohHMWnrD1DLsbqAhsbhM=
echo "Your secret: "
```

**Step 3:** Start the server:
```bash
# Basic (raw TCP):
veil-server -secret "" -listen ":8443"

# With TLS (recommended):
veil-server -secret "" -listen ":443" -transport tls -cert cert.pem -key key.pem

# Decoy mode (looks like real website):
veil-server -secret "" -listen ":443" -transport tls -cert cert.pem -key key.pem -decoy
```

**Step 4:** Connect from client:
```bash
veil-client -server YOUR_VPS_IP:8443 -secret ""
```

**Step 5 (optional):** Systemd service:
```ini
[Unit]
Description=Veil Protocol Server
After=network.target

[Service]
ExecStart=/usr/local/bin/veil-server -secret "YOUR_SECRET" -listen ":8443"
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

---

## Tutorial: Create a Custom Morph Profile

### Step 1: Capture Real Traffic
```bash
sudo tcpdump -i eth0 -w chrome_capture.pcap \
  "host example.com and tcp port 443" -c 10000
```

Tips: capture 1000+ packets, use the app normally during capture, filter by host/port.

### Step 2: Generate the Profile
```bash
veil-analyze -pcap chrome_capture.pcap -name my_chrome -out my_chrome.json
```

### Step 3: Compare Against Builtins
```bash
veil-analyze -compare my_chrome.json
```

### Step 4: Use Your Profile
```bash
veil-client -morph /path/to/my_chrome.json -server IP:PORT -secret "..."
```

### Step 5: Share with the Community!
1. Fork the repository
2. Add your JSON to morph/profiles/
3. Add a builtin function in morph/engine.go
4. Add to ListBuiltinProfiles() and GetBuiltinProfile()
5. Submit a PR

### Profile JSON Format
```json
{
  "name": "my_app",
  "description": "Description of what this mimics",
  "packet_sizes": {
    "buckets": [
      {"min": 24, "max": 100, "weight": 20.0},
      {"min": 100, "max": 500, "weight": 35.0},
      {"min": 500, "max": 1460, "weight": 45.0}
    ]
  },
  "timing": {
    "min_delay_ms": 0, "max_delay_ms": 500,
    "mean_delay_ms": 25, "jitter_ms": 40,
    "burst_size": 6, "burst_gap_ms": 100
  }
}
```

**Fields:** buckets weights should sum to ~100. burst_size = packets in rapid succession. burst_gap_ms = pause between bursts.

---

## License

MIT License
