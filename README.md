# Network Security Operations Incident Response Lab

Comprehensive network security operations project demonstrating SOC/NOC skills through 6 real-world scenarios: DNS attack investigation, network forensics, infrastructure troubleshooting, incident response, firewall management, and security scanning. Features hands-on experience with Wireshark, pfSense, DNS management, and vulnerability assessment.

The project simulates authentic enterprise security challenges including DNS poisoning attacks, network forensics investigations, infrastructure outages, access control failures, and compliance violations. Each scenario follows industry-standard incident response methodologies with detailed documentation, evidence collection, and remediation procedures.

**Key Capabilities Demonstrated:**
- Security incident detection and response
- Network forensics and threat hunting  
- Infrastructure troubleshooting and restoration
- Firewall management and access control
- Vulnerability assessment and compliance scanning
- Digital forensics and evidence preservation

## Languages and Utilities Used

- **Network Security:** pfSense Firewall, DNS Manager, Wireshark Protocol Analyzer
- **System Administration:** PowerShell, Windows Command Line (ipconfig, ping, traceroute, nslookup)
- **Infrastructure Management:** VyOS CLI, OSPF Configuration, NAT/Routing
- **Security Tools:** Nmap Port Scanner, Network Vulnerability Assessment
- **Remote Administration:** TightVNC Viewer, SSH, Remote Desktop

## Environments Used

- **Enterprise Infrastructure:** Windows Server 2019 (DNS/Domain Controller)
- **Network Security:** pfSense Firewall, VyOS Routers, DMZ Architecture  
- **Endpoint Systems:** Windows 10 Workstations, Ubuntu Linux Servers
- **Security Lab:** InfoSec Assessment Environment, Virtualized Network

## Detailed Incident Analysis

## Help Desk Ticket 1: DNS Redirection Issue

**Scenario**:
```
There are multiple reports of employees located in the USER_Net subnet who cannot get to www.wgu.edu, 
and the issue appears to be affecting the entire organization. They are being redirected to a suspicious site. 
A help desk technician states that the server team recently installed updates to DMZ_Server_3, which acts as 
the DNS server for the organization. The resolution must be organization-wide.
```

**Troubleshooting Process**:
1. Verified the issue by attempting to access www.wgu.edu, which resulted in a "Server Not Found" error
2. Accessed the DNS server on DMZ_Server_3 using TightVNC Viewer to examine its configuration
3. In DNS Manager, examined the forward lookup zone for wgu.edu and discovered both the root domain (wgu.edu) and the www subdomain were configured with Host (A) records pointing to 10.10.20.2
4. This incorrect IP address (10.10.20.2) explained why users were being redirected to a suspicious site - the DNS server was resolving wgu.edu to an IP address that hosted potentially malicious content
5. To resolve the issue, deleted the entire forward lookup zone for wgu.edu
6. After deletion, verified that users would now resolve wgu.edu via the organization's upstream DNS providers, which have the correct records
7. Verified the resolution by testing access to www.wgu.edu, which now successfully loaded the legitimate WGU website
8. Since DNS changes propagate throughout the organization automatically, this resolution is organization-wide as required

**Skills Demonstrated**:
- **Threat Detection:** Identified malicious DNS redirection affecting enterprise domain resolution
- **Digital Forensics:** Used DNS Manager to examine compromised zone configurations on critical infrastructure
- **Root Cause Analysis:** Discovered attacker-placed A records pointing wgu.edu to 10.10.20.2 (IOC)
- **Incident Containment:** Implemented emergency DNS zone deletion to restore legitimate resolution
- **Impact Assessment:** Verified organization-wide restoration of legitimate web access

**Tools Used**: DNS Manager, TightVNC, Network Connectivity Testing  
**[View Detailed Analysis →](./Ticket-01-DNS-Attack-Response/)**

---

## Help Desk Ticket 2: Illegal FTP Site Investigation

**Scenario**:
```
A complaint came in that a certain organization is hosting an illegal FTP site to download copyrighted 
software. The security team has provided a pcap file capturing all FTP traffic on the network. They have 
asked you to identify where the FTP site is being hosted.
```

**Troubleshooting Process**:
1. Opened the provided pcap file in Wireshark
2. Applied the display filter "ftp or ftp-data" to isolate only FTP-related traffic
3. Examined the filtered packets to identify FTP server communications
4. Found evidence of an FTP server at IP address 10.10.20.2 advertising itself as a "warez FTP service"
5. Observed successful anonymous login to the server
6. Identified navigation to common warez directories including "pub"
7. Found directory listing commands and evidence of file sharing activity
8. Confirmed the FTP server was explicitly labeled as providing "warez" content

**Skills Demonstrated**:
- **Network Forensics:** Analyzed PCAP files using Wireshark to identify unauthorized FTP activity
- **Protocol Analysis:** Applied advanced filtering ("ftp or ftp-data") to isolate malicious communications
- **Threat Intelligence:** Identified IOCs including FTP server at 10.10.30.2 hosting "warez" content
- **Evidence Collection:** Documented file transfer patterns, anonymous access, and directory structures
- **Compliance Reporting:** Prepared detailed findings for legal and regulatory requirements

**Tools Used**: Wireshark, Network Protocol Analysis, Digital Evidence Collection  
**[View Forensics Report →](./Ticket-02-Network-Forensics/)**

---

## Help Desk Ticket 3: Ubuntu Server Connectivity Issue

**Scenario**:
```
The host "Ubuntu_Server" cannot get to any of the assigned networks or the internet, which is preventing 
the server from pulling the required security patches. The resolution must be organization-wide.
```

**Troubleshooting Process**:
1. Used ping from Ubuntu_Server to test connectivity to loopback, local gateway, and internet addresses
2. Ran traceroute to 8.8.8.8 which revealed a routing loop between Router4 and Router5
3. Accessed Router4 and examined its routing table with the ip route command
4. Discovered Router4 had an incorrect default route pointing to 10.10.80.1 instead of 10.10.70.254
5. Identified lack of NAT configuration on Router4 and Router5 for internet traffic
6. Noted absence of dynamic routing protocols across the network
7. Implemented NAT masquerade rules on Router4 and Router5
8. Configured OSPF on all routers to provide dynamic routing across the organization
9. Verified connectivity with ping and traceroute from Ubuntu_Server to internet addresses

**Skills Demonstrated**:
- **Network Diagnostics:** Utilized ping/traceroute to identify routing loops between core infrastructure
- **Infrastructure Analysis:** Examined routing tables revealing misconfigured default gateway (10.10.80.1 → 10.10.70.254)
- **Protocol Configuration:** Implemented enterprise-wide OSPF dynamic routing for redundancy
- **Change Management:** Deployed NAT configurations across multiple edge routers
- **Service Restoration:** Restored internet connectivity for critical security patch management

**Tools Used**: Network Diagnostic Tools, VyOS CLI, OSPF Configuration, NAT Management  
**[View Infrastructure Analysis →](./Ticket-03-Infrastructure-Analysis/)**

---

## Help Desk Ticket 4: Windows Laptop Network Issue

**Scenario**:
```
A user complains that he cannot access the internet or network resources on his company laptop 
(Windows_Laptop_1) when it is connected via an ethernet cable to the office network.
```

**Troubleshooting Process**:
1. Verified Windows_Laptop_1 was connected but showing "No Internet access"
2. Ran Windows network troubleshooter, which identified "Ethernet doesn't have a valid IP configuration"
3. Used ipconfig to check the current IP address, revealing an autoconfiguration IP address (169.254.x.x)
4. Examined the network diagram to identify the correct IP addressing scheme
5. Changed IP assignment from automatic (DHCP) to manual and configured static IP settings:
   - IP address: 10.10.40.4
   - Subnet prefix length: 24
   - Default gateway: 10.10.40.254
   - DNS server: 10.10.20.3
6. Verified connectivity was restored and configuration was correct

**Skills Demonstrated**:
- **Desktop Support:** Applied Windows Network Troubleshooter for systematic diagnosis
- **Network Configuration:** Identified APIPA self-assignment (169.254.x.x) indicating DHCP service failure
- **Static IP Management:** Configured manual network settings (IP: 10.10.40.4/24, GW: 10.10.40.254, DNS: 10.10.20.3)
- **User Communication:** Provided clear technical guidance for immediate resolution
- **Service Verification:** Confirmed full network and internet access restoration

**Tools Used**: Windows Network Diagnostics, IP Configuration Management, Network Testing  
**[View Desktop Support Case →](./Ticket-04-Endpoint-Support/)**

---

## Help Desk Ticket 5: Firewall Access Issue

**Scenario**:
```
A coworker states that she worked on a ticket to allow access through the firewall to DMZ_Server_1. 
There is now no access to the server from any device outside its network.
```

**Troubleshooting Process**:
1. Attempted to ping DMZ_Server_1 and received "Request timed out"
2. Ran tracert to determine where the connection was failing (after hop 4)
3. Accessed the firewall console and used pfTop to examine connections
4. Identified a blocking rule: "block return out quick on em2 inet from any to 10.10.20.1"
5. Accessed the firewall web interface, confirmed and deleted the blocking rule
6. Verified connectivity to DMZ_Server_1 was restored

**Skills Demonstrated**:
- **Firewall Management:** Used pfSense CLI and web interface for rule analysis and modification
- **Traffic Analysis:** Employed pfTop for real-time connection monitoring and troubleshooting
- **Access Control Auditing:** Identified overly restrictive rule blocking legitimate DMZ communications
- **Security Rule Management:** Safely removed blocking rule "block return out quick on em2 inet from any to 10.10.20.1"
- **Change Documentation:** Maintained detailed audit trail for security compliance requirements

**Tools Used**: pfSense Firewall, pfTop Traffic Analysis, Access Control Management  
**[View Firewall Analysis →](./Ticket-05-Firewall-Management/)**

---

## Help Desk Ticket 6: Port Scanning Analysis

**Scenario**:
```
Your local cybersecurity team is requesting to know what ports are open on DMZ_Server_2 to identify 
services that may be running outside of the permitted services. Permitted services are 22/ssh, 
135/msrpc, 3389/ms-wbt-server, and 8080/http-proxy.
```

**Troubleshooting Process**:
1. Accessed DMZ_Server_2 directly via console. Ran ip addr to find its IP (10.10.20.2)
2. Used the nmap -p- command to scan for open ports
3. Compared scan results with the list of permitted services
4. Identified multiple unauthorized open ports and services:
   - Port 21/tcp (FTP)
   - Port 23/tcp (Telnet)
   - Port 80/tcp (HTTP)
   - Port 139/tcp (NetBIOS-SSN)
   - Port 145/tcp (UAAC)
   - Port 666/tcp (Doom)
   - Port 5483/tcp (Unknown)
   - Port 9000/tcp (CSListener)
   - Port 9001/tcp (tor-orport)
   - Port 9999/tcp (abyss)

**Skills Demonstrated**:
- **Vulnerability Assessment:** Conducted comprehensive nmap port scanning of critical infrastructure
- **Compliance Auditing:** Compared discovered services against approved baseline (22/SSH, 135/MSRPC, 3389/RDP, 8080/HTTP-Proxy)
- **Risk Analysis:** Identified 10+ unauthorized services including FTP, Telnet, HTTP, and suspicious ports (666/Doom, 9001/Tor)
- **Security Reporting:** Generated detailed findings with specific remediation recommendations
- **Hardening Guidance:** Provided actionable steps for service disable and host-based firewall implementation

**Tools Used**: Nmap Security Scanner, Port Analysis, Vulnerability Assessment  
**[View Security Assessment →](./Ticket-06-Vulnerability-Assessment/)**

## Professional Competencies

## SOC Analyst Skills
- Security incident detection and response
- Network forensics and threat hunting
- Digital evidence collection and preservation
- Threat intelligence analysis and IOC identification
- Security compliance auditing and reporting

## NOC Engineer Skills  
- Enterprise network infrastructure management
- Critical system restoration and business continuity
- Routing protocol configuration and optimization
- Firewall rule management and access control
- Change management and documentation procedures

## Help Desk Specialist Skills
- Desktop support and end-user troubleshooting
- Network connectivity diagnosis and resolution
- Clear technical communication and user guidance
- Systematic problem-solving methodologies
- Service verification and quality assurance

## Repository Structure

```
Network-Security-Operations-Incident-Response-Lab/
├── README.md                          # This file - project overview
├── METHODOLOGY.md                     # Incident response procedures
├── Ticket-01-DNS-Attack-Response/     # DNS poisoning investigation
├── Ticket-02-Network-Forensics/       # Copyright infringement case
├── Ticket-03-Infrastructure-Analysis/ # Critical server connectivity  
├── Ticket-04-Endpoint-Support/        # Desktop connectivity support
├── Ticket-05-Firewall-Management/     # Access control restoration
├── Ticket-06-Vulnerability-Assessment/# Security compliance scanning
├── Tools-and-Scripts/                 # Custom configurations
└── Documentation/                     # Technical references
```

## Technical Skills Demonstrated

- **Network Protocol Analysis:** with Wireshark packet inspection and filtering
- **DNS Security Management:** including zone configuration and attack remediation  
- **Enterprise Routing:** with OSPF implementation and NAT configuration
- **Firewall Administration:** using pfSense for access control and traffic management
- **Security Scanning:** with Nmap for vulnerability assessment and compliance validation
- **Incident Documentation:** following industry-standard security operation procedures

## Industry Relevance

This project simulates real-world scenarios encountered daily in enterprise security operations centers. Each incident represents authentic challenges faced by SOC analysts, NOC engineers, and IT support specialists, demonstrating practical skills directly applicable to cybersecurity careers.

The systematic approach to threat detection, investigation, and remediation showcases the critical thinking and technical expertise required for effective security operations in enterprise environments.

## Learning Outcomes

- **Incident Response:** Proven ability to detect, investigate, and remediate security incidents
- **Network Security:** Deep understanding of enterprise network security architectures  
- **Forensic Analysis:** Practical experience with digital forensics and evidence handling
- **Infrastructure Management:** Hands-on experience with critical network infrastructure
- **Compliance Operations:** Knowledge of security auditing and regulatory requirements
