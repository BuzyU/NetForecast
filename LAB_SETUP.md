# Isolated Lab Setup — Real Attack Traffic Generation

> **CAUTION**: Every command in this guide targets ONLY your own VMs on an isolated
> network you own. Never point any of these tools at networks, hosts, or services
> you don't own or have explicit written authorization to test.

---

## What This Does

Your model detects attacks by analyzing **flow-level features** extracted from real
packets. To demo it properly, you need real attack traffic flowing through your network
so the capture pipeline (`capture/live_capture.py`) can extract features and your model
can classify them.

This guide walks through generating traffic for each MITRE ATT&CK stage:

| Stage | What generates it | Tools |
|---|---|---|
| **Benign** | Normal browsing, file transfers | curl, wget, browser |
| **Reconnaissance** | Port scanning, service probing | nmap, hping3 |
| **Initial Access** | Brute-force login attempts | hydra, medusa |
| **Lateral Movement** | Internal spreading, credential reuse | psexec, smbclient, ssh |
| **C2** | Regular beaconing to external server | curl loop, custom script |
| **Exfiltration** | Large outbound data transfers | scp, curl, nc |

---

## Step 1: VM Network Setup (VirtualBox)

```
Host-Only Network (192.168.56.0/24)

   Attacker VM           Target VM
   Kali Linux            Metasploitable2
   192.168.56.10         192.168.56.20

   Your Windows Host (runs the dashboard + captures traffic)
   192.168.56.1
```

1. **Create Host-Only network**: VirtualBox → File → Host Network Manager → Create
   - Adapter IP: 192.168.56.1, mask: 255.255.255.0

2. **Attacker VM** — Kali Linux: https://www.kali.org/get-kali/#kali-virtual-machines
   - Import OVA, set network to "Host-Only Adapter", assign IP 192.168.56.10

3. **Target VM** — Metasploitable 2 (intentionally vulnerable):
   - https://sourceforge.net/projects/metasploitable/files/Metasploitable2/
   - Import, set to Host-Only, default creds: msfadmin/msfadmin

4. **Verify isolation**:
   ```bash
   ping 192.168.56.20   # Should succeed
   ping 8.8.8.8         # Should FAIL (no internet = isolated)
   ```

---

## Step 2: Install Npcap on Windows

Download from https://npcap.com/#download
Check "Install in WinPcap API-compatible Mode" during install.

---

## Step 3: Start Detection Pipeline (3 terminals)

Terminal 1 — Backend:
```powershell
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Terminal 2 — Live Capture (Run as Administrator):
```powershell
python capture/live_capture.py --list-interfaces
python capture/live_capture.py --interface "VirtualBox Host-Only Ethernet Adapter" --api http://localhost:8000
```

Terminal 3 — Frontend:
```powershell
cd frontend && npm run dev
```

---

## Step 4: Generate Real Attack Traffic (on Kali VM)

### 4.1 — Benign Traffic (Background)
```bash
for i in $(seq 1 20); do curl -s http://192.168.56.20/ > /dev/null; sleep 2; done
```

### 4.2 — Reconnaissance (Port Scanning)
```bash
nmap -sS -T4 -p 1-1000 192.168.56.20
nmap -sV -p 21,22,23,25,80,139,445,3306,5432 192.168.56.20
nmap -O 192.168.56.20
nmap -A -T4 192.168.56.20
```

### 4.3 — Initial Access (Brute Force)
```bash
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt -t 4 -f 192.168.56.20 ssh
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt -t 4 -f 192.168.56.20 ftp
```

### 4.4 — Lateral Movement
```bash
smbclient -L //192.168.56.20 -N
sshpass -p 'msfadmin' ssh -o StrictHostKeyChecking=no msfadmin@192.168.56.20 \
    "whoami; id; uname -a; cat /etc/passwd; ls -la /home/"
```

### 4.5 — Command & Control (Beaconing)
```bash
for i in $(seq 1 30); do
    curl -s -o /dev/null http://192.168.56.20/
    sleep 10  # Regular interval = beaconing signature
done
```

### 4.6 — Exfiltration (Data Theft)
```bash
dd if=/dev/urandom of=/tmp/stolen_data.bin bs=1M count=50 2>/dev/null
sshpass -p 'msfadmin' scp /tmp/stolen_data.bin msfadmin@192.168.56.20:/tmp/
rm /tmp/stolen_data.bin
```

---

## Alternative: Replay CIC-IDS2017 PCAPs

```powershell
python capture/live_capture.py --pcap "path/to/Friday-WorkingHours.pcap" --api http://localhost:8000 --speed 0.001
```

---

## Safety Checklist

- VMs are on Host-Only network with NO internet access
- Target VM is intentionally vulnerable (Metasploitable)
- All commands target only 192.168.56.x (your own IPs)
- Not connected to any production or shared network
