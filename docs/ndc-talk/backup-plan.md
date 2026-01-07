# Backup Plan - When the Demo Gods Are Angry

## The Golden Rule
**Always have a backup. Never panic publicly.**

---

## Scenario 1: Testbed Won't Start

### Signs
- Containers failing to start
- "Connection refused" errors
- High CPU/memory

### Quick Fix (30 seconds)
```bash
# Try restart
docker compose restart

# Check what's wrong
docker compose logs --tail=50
```

### If That Fails
**Switch to pre-recorded video**

> "The demo gods are not with us today. Let me show you a recording I made earlier..."

[Play `demo-backup.mp4`]

---

## Scenario 2: Wazuh Dashboard Won't Load

### Signs
- 502 Bad Gateway
- Infinite loading
- White screen

### Quick Fix (20 seconds)
```bash
docker restart wazuh-dashboard
# Wait 10 seconds
```

### If That Fails
**Use API instead**

```bash
# Show alerts via API (in terminal)
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/alerts?limit=5" | jq '.data.affected_items[] | {rule: .rule.id, desc: .rule.description}'
```

> "Dashboard is having a moment, but Wazuh is still detecting. Here's the API view..."

---

## Scenario 3: Alert Doesn't Appear

### Signs
- Attack runs successfully
- No alert in dashboard
- Awkward silence

### Quick Fix (15 seconds)
```bash
# Trigger manually in another terminal
docker exec cloud-workload logger "IMDS ACCESS: 169.254.169.254/iam/security-credentials"
```

### If That Fails
**Show existing alert**

> "Let me show you an alert I generated earlier..."

[Filter to show pre-existing alert or use screenshot]

---

## Scenario 4: IMDS Mock Not Responding

### Signs
- `curl` hangs or times out
- "Connection refused"

### Quick Fix (15 seconds)
```bash
docker restart mock-imds
sleep 3
curl http://localhost:1338/
```

### If That Fails
**Explain what would happen**

> "Our mock service is down, but let me walk you through what the output would be..."

[Show slide with IMDS output screenshot]

---

## Scenario 5: Network Issues

### Signs
- Can't connect to anything
- DNS failures
- "Network unreachable"

### Quick Fix
```bash
# Check Docker networking
docker network ls
docker network inspect machine-identity-discovery_cloud_net

# Recreate networks
docker compose down
docker compose up -d
```

### If That Fails
**Switch to video or slides**

> "Looks like we have some network issues. Let me show you the pre-recorded version..."

---

## Scenario 6: Everything is Broken

### Signs
- Multiple failures
- Errors everywhere
- Audience getting restless

### Recovery Plan
1. **Stop trying to fix** (max 60 seconds of troubleshooting live)
2. **Acknowledge gracefully**: "The demo gods are not with us today"
3. **Switch to video immediately**
4. **Keep talking while video plays**

### Script for Total Failure
> "Live demos are always an adventure. Let me show you a recording I prepared. The good news is, this testbed is all open source - you can run it yourselves and hopefully have better luck."

[Play backup video]

> "What you're seeing here is exactly what I was going to show you..."

---

## Pre-prepared Backup Materials

### 1. Demo Video (`demo-backup.mp4`)
- Full recording of Demo 2
- Duration: 8 minutes
- Location: `docs/ndc-talk/media/demo-backup.mp4`

### 2. Screenshot Sequence
- IMDS output screenshot
- Wazuh alert screenshot
- Alert details screenshot
- Location: `docs/ndc-talk/media/screenshots/`

### 3. Text Outputs
Pre-captured outputs for copy-paste demonstration:

**IMDS Credentials Output**:
```json
{
  "Code": "Success",
  "AccessKeyId": "ASIADEMOTESTBED00001",
  "SecretAccessKey": "wJalrXUtnFEMI_DEMO_IMDS_STOLEN_KEY",
  "Token": "FwoGZXIvYXdzEBYaDEMOTOKENFORTESTING...",
  "Expiration": "2026-01-06T12:00:00Z"
}
```

**Alert JSON**:
```json
{
  "rule": {
    "id": "100651",
    "level": 12,
    "description": "NHI: AWS IMDS IAM credential request - CREDENTIAL THEFT ATTEMPT"
  },
  "agent": {
    "name": "cloud-workload"
  },
  "mitre": {
    "technique": ["T1552.005"]
  }
}
```

---

## Before the Talk Checklist

### Day Before
- [ ] Record backup video
- [ ] Capture screenshots
- [ ] Test video playback
- [ ] Save text outputs

### Hour Before
- [ ] Start testbed fresh
- [ ] Generate test alert
- [ ] Verify video file accessible
- [ ] Verify screenshots accessible
- [ ] Test display connection

### 5 Minutes Before
- [ ] Testbed running
- [ ] Dashboard open
- [ ] Terminal ready
- [ ] Backup video cued
- [ ] Water available
- [ ] Deep breaths

---

## The Speaker's Mantra

**Things will break. That's okay.**

- A failed demo with graceful recovery > a perfect demo
- The audience remembers your composure, not the error
- Everyone has experienced demo failures
- Backup materials show professionalism

---

## Post-Incident

If the demo failed:

1. **Don't apologize repeatedly**
   - Acknowledge once, move on

2. **In Q&A**: "For those who want to see the live demo, I'll be at the Wazuh booth later"

3. **On social media**: Post the video with "Demo didn't cooperate during the talk, but here's what it looks like when it works!"

4. **Learn**: Document what broke and why for next time
