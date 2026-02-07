# Forescout Certified Associate (FCA) Study Guide
## Complete Product Portfolio & Exam Preparation — 2026 Edition

---

## Table of Contents
1. [The Forescout 4D Platform](#the-forescout-4d-platform)
2. [Core Products (Exam Focus)](#core-products-exam-focus)
   - [eyeSight](#1-eyesight---visibility)
   - [eyeControl](#2-eyecontrol---enforcement)
   - [eyeSegment](#3-eyesegment---segmentation)
   - [eyeExtend](#4-eyeextend---integrations)
3. [Specialized Products](#specialized-products)
   - [eyeAlert](#5-eyealert---threat-detection--response)
   - [eyeInspect](#6-eyeinspect---oticsscada-security)
   - [eyeFocus](#7-eyefocus---asset-intelligence)
   - [eyeScope](#8-eyescope---cloud-console)
   - [eyeSentry](#9-eyesentry---exposure-management)
   - [Flyaway Kit](#10-flyaway-kit---portable-deployment)
4. [Key Concepts for the Exam](#key-concepts-for-the-exam)
5. [Policy Engine Deep Dive](#policy-engine-deep-dive)
6. [Deployment & Architecture](#deployment--architecture)
7. [Use Cases & Solutions](#use-cases--solutions)
8. [Exam Tips & Practice Questions](#exam-tips--practice-questions)

---

## The Forescout 4D Platform

The **Forescout 4D Platform™** is the unified architecture that powers all Forescout products. The "4D" represents:

| Dimension | Meaning | What It Does |
|-----------|---------|--------------|
| **Discover** | See everything | Agentless discovery of all IP-connected devices |
| **Assess** | Understand risk | Classify, profile, and evaluate device posture |
| **Control** | Enforce policy | Apply network access control and segmentation |
| **Govern** | Orchestrate response | Automate workflows and integrate with security ecosystem |

### Platform Capabilities
- **Device Agnostic**: Sees IT, OT, IoT, IoMT — managed and unmanaged
- **Agentless First**: No software to install on endpoints
- **Real-Time**: Continuous monitoring, not periodic scans
- **Zero Trust Ready**: Supports UZTNA (Universal Zero Trust Network Access)

---

## Core Products (Exam Focus)

These four products form the foundation of the FCA exam.

---

### 1. eyeSight — Visibility

> **Tagline**: *"See every device the moment it connects"*

#### What It Does
eyeSight provides **real-time, agentless discovery and classification** of every device on your network — whether managed, unmanaged, IoT, OT, or rogue.

#### Key Capabilities

| Capability | Description |
|------------|-------------|
| **Device Discovery** | Finds all IP-connected devices using passive and active methods |
| **Classification** | Identifies device type, OS, manufacturer, model |
| **Asset Inventory** | Maintains real-time database of all network assets |
| **Passive Techniques** | SPAN/mirror ports, DHCP fingerprinting, NetFlow |
| **Active Techniques** | SNMP, WMI, SSH, NMAP-style probing (configurable) |

#### How It Discovers Devices
1. **Network Traffic Analysis** — Watches packets on SPAN ports
2. **DHCP Snooping** — Captures DHCP requests to see new devices
3. **ARP Monitoring** — Tracks MAC-to-IP mappings
4. **Switch Integration** — Queries switches via SNMP for connected MACs
5. **Active Directory** — Pulls managed device information
6. **Credential-Based Scans** — WMI (Windows), SSH (Linux), SNMP (network devices)

#### Device Classification Types
- **Managed IT**: Windows, macOS, Linux with corporate agents
- **Unmanaged IT**: Personal laptops, contractor devices
- **IoT**: Cameras, printers, smart TVs, badge readers
- **OT/ICS**: PLCs, HMIs, SCADA systems (basic classification)
- **IoMT**: Medical devices (infusion pumps, imaging systems)
- **Network Infrastructure**: Switches, routers, wireless APs

#### Exam Focus Areas
- [ ] Understand passive vs. active discovery methods
- [ ] Know how eyeSight integrates with switches (SNMP, 802.1X)
- [ ] Understand device classification hierarchy
- [ ] Know the difference between managed and unmanaged devices

---

### 2. eyeControl — Enforcement

> **Tagline**: *"Enforce access based on who and what devices are"*

#### What It Does
eyeControl enables **policy-based network access control** — deciding what devices can access, what they can reach, and what happens when they violate policy.

#### Key Capabilities

| Capability | Description |
|------------|-------------|
| **Network Access Control (NAC)** | Allow, block, or limit device access |
| **VLAN Assignment** | Move devices to appropriate network segments |
| **ACL Management** | Push access control lists to switches/firewalls |
| **Quarantine** | Isolate non-compliant or suspicious devices |
| **Guest Registration** | Onboard guest devices with captive portal |
| **802.1X Integration** | Works with RADIUS for port-based authentication |
| **ActiveResponse** | Take direct actions on endpoints |

#### Enforcement Methods

| Method | How It Works | Use Case |
|--------|--------------|----------|
| **VLAN Steering** | Changes device's VLAN via SNMP/RADIUS | Segment IoT from corporate |
| **ACL Push** | Installs access rules on switch ports | Block specific traffic |
| **802.1X CoA** | Change of Authorization via RADIUS | Dynamic policy updates |
| **DNS Enforcement** | Redirects DNS to block destinations | Guest captive portal |
| **ActiveResponse** | Runs scripts/commands on Windows endpoints | Kill processes, logout users |
| **Firewall Integration** | Pushes rules to Palo Alto, Cisco, etc. | Block at perimeter |

#### Policy Workflow
```
Device Connects → eyeSight Sees It → eyeControl Evaluates Policy → Action Applied
     ↓                    ↓                      ↓                       ↓
  [Discovery]      [Classification]        [Authorization]         [Enforcement]
                                           [Compliance Check]
```

#### Compliance Checks You Can Perform
- Antivirus installed and updated?
- OS patches current?
- Encryption enabled?
- Corporate agent present?
- Firewall active?
- Specific software installed/not installed?

#### Exam Focus Areas
- [ ] Understand the policy engine workflow
- [ ] Know all enforcement methods (VLAN, ACL, 802.1X, DNS)
- [ ] Understand compliance policy creation
- [ ] Know how quarantine and remediation work
- [ ] Understand guest registration workflow

---

### 3. eyeSegment — Segmentation

> **Tagline**: *"See, simulate, and enforce network segmentation"*

#### What It Does
eyeSegment provides **visibility into traffic flows** and helps design, simulate, and enforce **network segmentation policies** — critical for Zero Trust.

#### Key Capabilities

| Capability | Description |
|------------|-------------|
| **Traffic Flow Visualization** | See what talks to what across your network |
| **Segmentation Design** | Define zones and allowed communication paths |
| **Policy Simulation** | Test policies before enforcement ("what-if" mode) |
| **Micro-Segmentation** | Granular control down to individual device types |
| **Compliance Monitoring** | Alert on violations of segmentation policy |
| **Integration** | Works with firewalls and SDN for enforcement |

#### Segmentation Zones (Examples)
| Zone | Contains |
|------|----------|
| **Corporate IT** | Managed Windows/Mac endpoints |
| **IoT Devices** | Cameras, printers, smart devices |
| **Guest Network** | Visitor and contractor devices |
| **OT/Manufacturing** | PLCs, HMIs, SCADA |
| **Medical Devices** | Infusion pumps, imaging |
| **Server/Data Center** | Critical applications |

#### Traffic Matrix Example
```
            → Corporate   → IoT   → Guest   → OT   → Servers
Corporate       ✓           ✓       ✗        ✗        ✓
IoT             ✗           ✓       ✗        ✗        ✗
Guest           ✗           ✗       ✓        ✗        ✗
OT              ✗           ✗       ✗        ✓        ✗
Servers         ✓           ✗       ✗        ✗        ✓
```

#### Exam Focus Areas
- [ ] Understand network segmentation concepts
- [ ] Know how to define zones and segments
- [ ] Understand traffic flow visualization
- [ ] Know the relationship between eyeSegment and eyeControl

---

### 4. eyeExtend — Integrations

> **Tagline**: *"Extend visibility and control across your security stack"*

#### What It Does
eyeExtend is a **collection of integration modules** that connect Forescout to third-party security tools, enabling **bi-directional data sharing** and **automated workflows**.

#### Integration Categories

| Category | Example Integrations |
|----------|---------------------|
| **Endpoint Security** | CrowdStrike, Carbon Black, Microsoft Defender |
| **Firewall/NGFW** | Palo Alto Networks, Cisco ASA, Check Point |
| **SIEM** | Splunk, IBM QRadar, Microsoft Sentinel |
| **ITSM** | ServiceNow, Jira |
| **Identity** | Microsoft Active Directory, Okta |
| **Vulnerability** | Qualys, Rapid7, Tenable |
| **Cloud** | AWS, Azure, Google Cloud |
| **NAC/Identity** | Cisco ISE |
| **Endpoint Management** | Microsoft Intune, SCCM, VMware Workspace ONE |

#### How Integrations Work

**Inbound Data** (from 3rd party → Forescout):
- Vulnerability scan results
- EDR detection alerts
- Patch status from endpoint management
- User identity from AD

**Outbound Actions** (from Forescout → 3rd party):
- Trigger endpoint scan
- Create ServiceNow ticket
- Push firewall rule
- Initiate EDR containment

#### Example Workflow
```
1. CrowdStrike detects malware on device
2. eyeExtend receives alert
3. eyeControl quarantines device (VLAN change)
4. ServiceNow ticket created automatically
5. Admin notified
```

#### Exam Focus Areas
- [ ] Know the major integration categories
- [ ] Understand bi-directional data flow
- [ ] Know how integrations enhance automation
- [ ] Understand the value of ecosystem connectivity

---

## Specialized Products

These products are NOT heavily tested on the FCA exam but are part of the complete platform.

---

### 5. eyeAlert — Threat Detection & Response

> **Tagline**: *"Eliminate alert fatigue, accelerate threat response"*

#### What It Does
eyeAlert is Forescout's **XDR/SIEM replacement** — it uses **Agentic AI** to automate detection, investigation, and response to threats across IT, OT, and IoT.

#### Key Capabilities
| Feature | Description |
|---------|-------------|
| **Data Ingestion** | 180+ sources (firewalls, EDR, cloud, etc.) |
| **Threat Intelligence** | 70+ global sources, scored IOCs |
| **MITRE ATT&CK Mapping** | Aligns detections to framework |
| **UEBA** | User/Entity Behavior Analytics for anomaly detection |
| **SOAR** | Built-in orchestration and automation |
| **Case Management** | Integrates with ServiceNow, Jira, TheHive |
| **AI-Powered** | Agentic AI reduces SOC workload by 75% |

#### Data Sources Supported
- EDR (CrowdStrike, Defender, Carbon Black)
- Firewalls (Palo Alto, Cisco, Fortinet)
- Cloud (AWS, Azure, GCP, M365)
- Network (DNS, DHCP, proxy logs)
- Identity (AD authentication, IAM)
- Forescout (eyeSight, eyeInspect)

---

### 6. eyeInspect — OT/ICS/SCADA Security

> **Tagline**: *"Deep visibility for operational technology"*

#### What It Does
eyeInspect provides **specialized visibility and threat detection for OT/ICS environments** — including legacy serial devices that standard IT tools cannot see.

#### Key Capabilities
| Feature | Description |
|---------|-------------|
| **OT Device Discovery** | Finds PLCs, HMIs, RTUs, sensors |
| **Serial Device Support** | Sees devices on serial (RS-232/485) networks |
| **Protocol Analysis** | Deep packet inspection for ICS protocols |
| **Anomaly Detection** | ML-based behavioral baselines |
| **Threat Indicators** | 1000+ ICS-specific signatures |
| **MITRE ATT&CK for ICS** | Maps threats to ICS framework |
| **Passive Deployment** | Non-intrusive — won't disrupt operations |

#### OT Protocols Monitored
- Modbus TCP/RTU
- DNP3
- BACnet
- EtherNet/IP
- OPC UA/DA
- Siemens S7
- IEC 61850/60870-5-104

---

### 7. eyeFocus — Asset Intelligence

> **Tagline**: *"Quantify and prioritize device risk"*

#### What It Does
eyeFocus provides **deep asset intelligence and risk scoring** for unmanaged devices — especially IoT, OT, and medical devices (IoMT).

#### Key Capabilities
| Feature | Description |
|---------|-------------|
| **Multi-Factor Risk Score** | Continuous risk assessment per device |
| **Deep Packet Inspection** | Patented DPI for device profiling |
| **90-Day History** | Track configuration and risk changes over time |
| **Vulnerability Correlation** | Links devices to known CVEs |
| **Compliance Mapping** | Align to regulatory frameworks |

---

### 8. eyeScope — Cloud Console

> **Tagline**: *"Unified cloud visibility for distributed environments"*

#### What It Does
eyeScope extends **eyeSight to the cloud** — providing a unified console for organizations with multiple sites and cloud-native visibility requirements.

#### Key Capabilities
| Feature | Description |
|---------|-------------|
| **Cloud-Native Console** | SaaS-based management |
| **Gen-AI Reports** | Executive-level security posture reports |
| **Zero Trust Inventory** | Agentless IT/IoT/rogue device visibility |
| **Real-Time Alerts** | System health and security notifications |

---

### 9. eyeSentry — Exposure Management

> **Tagline**: *"Uncover hidden risks across your attack surface"*

#### What It Does
eyeSentry is a **cloud-native exposure management** solution (announced November 2025) that combines active and passive discovery to find hidden risks.

#### Key Capabilities
| Feature | Description |
|---------|-------------|
| **Active + Passive Discovery** | Comprehensive asset finding |
| **Exposure Identification** | Finds misconfigurations and vulnerabilities |
| **IT/IoT/IoMT Coverage** | Broad device support |
| **Cloud-Native** | SaaS deployment |

---

### 10. Flyaway Kit — Portable Deployment

> **Tagline**: *"Visibility anywhere, instantly"*

#### What It Does
The Flyaway Kit is a **portable, rapid-deployment** Forescout solution for incident response, audits, or temporary site assessments.

#### Use Cases
- Incident response team deployment
- Acquisition due diligence
- Temporary facility monitoring
- Compliance audits

---

## Key Concepts for the Exam

### Agentless vs. Agent-Based

| Approach | Description | Pros | Cons |
|----------|-------------|------|------|
| **Agentless** | No software on endpoints | Sees unmanaged devices, no deployment | Less deep visibility |
| **SecureConnector** | Lightweight Forescout agent | Deep compliance checks | Requires deployment |

### Network Integration Methods

| Method | Purpose |
|--------|---------|
| **SPAN/Mirror Port** | Passive traffic analysis |
| **SNMP** | Query switches for MAC tables, push VLAN changes |
| **802.1X/RADIUS** | Port-based authentication and CoA |
| **NetFlow/IPFIX** | Traffic metadata analysis |
| **API Integrations** | Connect to other security tools |

### Zero Trust Network Access (ZTNA/UZTNA)
Forescout's approach to Zero Trust:
1. **Never trust, always verify** — Every device verified before access
2. **Least privilege** — Minimum necessary access
3. **Continuous monitoring** — Ongoing posture assessment
4. **Micro-segmentation** — Granular network controls

---

## Policy Engine Deep Dive

The **Policy Engine** is the heart of Forescout. Master this for the exam.

### Policy Structure
```
POLICY
  └── RULE (Main Rule)
        ├── Condition (IF device matches...)
        ├── Sub-Rules (Additional conditions)
        └── Actions (THEN do...)
```

### Condition Types
| Type | Example |
|------|---------|
| **Device Property** | OS = Windows 10 |
| **Network Location** | VLAN = 100 |
| **Compliance State** | Antivirus = Not Running |
| **Time-Based** | After business hours |
| **Classification** | Device Type = Printer |

### Boolean Logic
- **AND**: All conditions must be true
- **OR**: Any condition can be true
- **NOT**: Invert the condition

### Irresolvables
When a condition **cannot be evaluated** (e.g., device doesn't respond to WMI query), the result is "irresolvable."

**Handling Options:**
- Treat as TRUE
- Treat as FALSE
- Wait and retry

### Policy Types

| Policy Type | Purpose | Example |
|-------------|---------|---------|
| **Classification** | Identify device type | "If MAC starts with 00:50:56 → VMware VM" |
| **Authorization** | Decide if allowed | "If not in AD → Deny" |
| **Compliance** | Check posture | "If no antivirus → Non-compliant" |
| **Response** | Take action | "If non-compliant → Move to quarantine VLAN" |

### Action Types

| Action | What It Does |
|--------|--------------|
| **Assign to VLAN** | Move device to specific network segment |
| **Apply ACL** | Push access control rules |
| **HTTP Notification** | Show user a web page (captive portal) |
| **Send Email** | Alert administrator |
| **Run Script** | Execute remediation commands |
| **Create Ticket** | Open ServiceNow/Jira incident |

---

## Deployment & Architecture

### Component Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Enterprise Manager                   │
│           (Central Management, Policy)              │
└────────────────────────┬────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│   Appliance  │ │   Appliance  │ │   Appliance  │
│   (Site A)   │ │   (Site B)   │ │   (Site C)   │
└──────────────┘ └──────────────┘ └──────────────┘
        │                │                │
    [Switch]         [Switch]         [Switch]
        │                │                │
    [Devices]        [Devices]        [Devices]
```

### Deployment Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Layer 2 (Inline)** | Appliance between devices and network | Maximum control |
| **Layer 3 (Out-of-Band)** | Appliance on SPAN port, controls via SNMP | Most common |
| **Virtual** | VM-based appliance | Cloud/virtualized environments |

### Switch Integration Requirements
- **SNMP v2c or v3**: Read MAC tables, push VLAN changes
- **802.1X support**: For RADIUS-based enforcement
- **SPAN/Mirror ports**: For passive visibility

---

## Use Cases & Solutions

### By Use Case

| Use Case | Primary Products | Key Features |
|----------|-----------------|--------------|
| **Asset Inventory** | eyeSight, eyeFocus | Complete device visibility |
| **IoT Security** | eyeSight, eyeControl | Discover and segment IoT |
| **OT Security** | eyeInspect, eyeFocus | Deep OT/ICS visibility |
| **Medical Device Security** | eyeSight, eyeFocus | IoMT discovery and risk |
| **Network Access Control** | eyeControl | Policy-based access |
| **Network Segmentation** | eyeSegment | Traffic flow and enforcement |
| **UZTNA** | eyeControl, eyeAlert | Zero Trust implementation |
| **Device Compliance** | eyeControl | Posture assessment |
| **Security Automation** | eyeExtend, eyeAlert | Workflow orchestration |
| **SIEM Modernization** | eyeAlert | XDR/SIEM replacement |

### By Industry

| Industry | Key Concerns | Relevant Products |
|----------|--------------|-------------------|
| **Healthcare** | Medical devices, HIPAA | eyeSight, eyeFocus, eyeControl |
| **Manufacturing** | OT/ICS, uptime | eyeInspect, eyeFocus |
| **Financial Services** | Compliance, segmentation | eyeControl, eyeSegment |
| **Energy/Utilities** | Critical infrastructure | eyeInspect, eyeAlert |
| **Government** | Zero Trust mandates | eyeControl, eyeSegment |
| **Education** | BYOD, guest access | eyeSight, eyeControl |

---

## Exam Tips & Practice Questions

### Exam Format
- **Type**: Multiple choice + scenario-based
- **Duration**: ~90 minutes
- **Focus**: eyeSight, eyeControl, policy engine, deployment

### Study Priorities

| Priority | Topic | Weight |
|----------|-------|--------|
| 🔴 High | Policy engine mechanics | 25% |
| 🔴 High | eyeControl enforcement methods | 20% |
| 🔴 High | eyeSight discovery methods | 15% |
| 🟡 Medium | Deployment architecture | 15% |
| 🟡 Medium | Switch integration (SNMP, 802.1X) | 10% |
| 🟢 Low | eyeSegment concepts | 10% |
| 🟢 Low | eyeExtend integrations | 5% |

### Practice Questions

**Q1**: A device is discovered but eyeSight cannot determine if antivirus is running. The compliance check shows "irresolvable." What should you configure?
- A) Fail open (treat as compliant)
- B) Fail closed (treat as non-compliant)
- C) Retry with different credentials
- D) All of the above depending on policy

**Answer**: D — Irresolvable handling is policy-dependent.

---

**Q2**: Which enforcement method would you use to redirect an unauthenticated guest to a captive portal?
- A) VLAN assignment
- B) ACL push
- C) DNS enforcement
- D) 802.1X CoA

**Answer**: C — DNS enforcement redirects web traffic to the portal.

---

**Q3**: A manufacturing company needs to monitor PLCs and HMIs without disrupting production. Which product should they use?
- A) eyeSight
- B) eyeControl
- C) eyeInspect
- D) eyeAlert

**Answer**: C — eyeInspect provides passive OT monitoring.

---

**Q4**: What protocol does Forescout primarily use to read switch MAC address tables and change VLANs?
- A) SSH
- B) SNMP
- C) NetFlow
- D) Syslog

**Answer**: B — SNMP is the primary switch integration protocol.

---

**Q5**: A policy checks if a device is running Windows 10 AND has antivirus installed. The device is Windows 10 but antivirus status is unknown. Using default Boolean logic, what is the result?
- A) TRUE
- B) FALSE
- C) Irresolvable
- D) Error

**Answer**: C — AND logic with any irresolvable = irresolvable.

---

## Additional Resources

- **Official Training**: [Forescout Academy](https://www.forescout.com/services/training/)
- **Documentation**: [docs.forescout.com](https://docs.forescout.com)
- **Community**: [Forescout Community Portal](https://community.forescout.com)
- **Threat Research**: [Forescout Vedere Labs](https://www.forescout.com/research-labs/)

---

*Last Updated: February 2026*
*Document Version: 1.0*
