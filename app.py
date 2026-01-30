from flask import Flask, render_template, jsonify, send_file, send_from_directory
import sqlite3
import os

app = Flask(__name__)

DATABASE = 'practicals.db'

# Create downloads directory for storing downloadable files
DOWNLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'downloads')
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

def get_db():
    """Connect to the database"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with practicals data"""
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Create practicals table
    cursor.execute('''
        CREATE TABLE practicals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            theory TEXT NOT NULL,
            steps TEXT NOT NULL
        )
    ''')
    
    # Insert all practicals
    practicals_data = [
        {
            'title': 'Encrypting and Decrypting Data Using OpenSSL',
            'category': 'Cryptography',
            'theory': '''OpenSSL is an open source project that provides a robust, commercial-grade, and full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols. It is also a general-purpose cryptography library.

Key Concepts:
- AES-256-CBC: Advanced Encryption Standard with 256-bit key in Cipher Block Chaining mode
- Base64 Encoding: Converts binary data to ASCII string format for easy transmission
- Encryption: Process of converting plaintext to ciphertext
- Decryption: Process of converting ciphertext back to plaintext

Security Note: The method in this lab uses weak key derivation and should be used for instructional purposes only.''',
            'steps': '''# Step 1: Navigate to the working directory
cd ./lab.support.files/

# Step 2: View the file to be encrypted
cat letter_to_grandma.txt

# Step 3: Encrypt the file using AES-256-CBC
openssl aes-256-cbc -in letter_to_grandma.txt -out message.enc
# Enter password when prompted
# Verify password when prompted

# Step 4: View encrypted file (will show binary symbols)
cat message.enc

# Step 5: Encrypt with Base64 encoding for readability
openssl aes-256-cbc -a -in letter_to_grandma.txt -out message.enc
# Enter password when prompted
# Verify password when prompted

# Step 6: View Base64-encoded encrypted file
cat message.enc

# Step 7: Decrypt the message
openssl aes-256-cbc -a -d -in message.enc -out decrypted_letter.txt
# Enter the same password used for encryption

# Step 8: View decrypted content
cat decrypted_letter.txt'''
        },
        {
            'title': 'Snort and Firewall Rules',
            'category': 'Network Security',
            'theory': '''Intrusion Detection Systems (IDS) and firewalls are critical security tools for monitoring and controlling network traffic.

Snort: An open-source network intrusion detection system that analyzes network packets against predefined rules.

Firewall Components:
- Matching Component: Specifies packet elements of interest (source, destination, protocols, ports)
- Action Component: Defines what to do when a match is found (accept, drop, log)

iptables Chains:
- INPUT: Traffic destined to the firewall itself
- OUTPUT: Traffic originated from the firewall
- FORWARD: Traffic passing through the firewall

Design Philosophy: Drop by default, explicitly allow required traffic.''',
            'steps': '''# Step 1: Configure network as DHCP
sudo ./lab.support.files/scripts/configure_as_dhcp.sh
# Enter password: cyberops

# Step 2: Verify network connectivity
ifconfig
ping www.cisco.com
# Press Ctrl+C to stop

# Step 3: Start Mininet environment
sudo ./lab.support.files/scripts/cyberops_extended_topo_no_fw.py

# Step 4: Open R1 shell from mininet
mininet> xterm R1

# Step 5: Start Snort IDS on R1
./lab.support.files/scripts/start_snort.sh

# Step 6: Open shells for H5 and H10
mininet> xterm H5
mininet> xterm H10

# Step 7: Start malware server on H10
./lab.support.files/scripts/mal_server_start.sh

# Step 8: Verify server is running
netstat -tunpa

# Step 9: Open another R1 terminal
mininet> xterm R1

# Step 10: Monitor Snort alerts in real-time
tail -f /var/log/snort/alert

# Step 11: Download malware from H5 (to trigger alert)
wget 209.165.202.133:6666/W32.Nimda.Amm.exe

# Step 12: Capture traffic with tcpdump on H5
tcpdump -i H5-eth0 -w nimda.download.pcap &

# Step 13: Download malware again
wget 209.165.202.133:6666/W32.Nimda.Amm.exe

# Step 14: Stop tcpdump
fg
# Press Ctrl+C

# Step 15: List current iptables rules
iptables -L -v

# Step 16: Add firewall rule to block malicious server
iptables -I FORWARD -p tcp -d 209.165.202.133 --dport 6666 -j DROP

# Step 17: Verify rule was added
iptables -L -v

# Step 18: Try downloading again (should fail)
wget 209.165.202.133:6666/W32.Nimda.Amm.exe
# Press Ctrl+C to cancel

# Step 19: Terminate Mininet
quit

# Step 20: Clean up Mininet processes
sudo mn -c'''
        },
        {
            'title': 'Extract an Executable from PCAP',
            'category': 'Forensics',
            'theory': '''Packet Capture (PCAP) files contain network traffic data that can be analyzed for security investigations. Wireshark is a powerful tool for analyzing PCAP files.

Key Concepts:
- PCAP Format: Standard format for capturing network packets
- Wireshark: GUI tool for packet analysis
- TCP Stream: Following the complete conversation between two endpoints
- HTTP Object Extraction: Retrieving files transferred over HTTP

Use Cases:
- Malware analysis
- Incident response
- Network troubleshooting
- Evidence collection

The file command helps identify file types, which is crucial for malware analysis.''',
            'steps': '''# Step 1: Navigate to pcaps directory
cd lab.support.files/pcaps

# Step 2: List available PCAP files
ls -l

# Step 3: Open PCAP file in Wireshark
wireshark nimda.download.pcap &

# Step 4: Filter for HTTP traffic
# In Wireshark filter box, enter: http

# Step 5: Select the HTTP GET request packet
# Look for packet with "GET /W32.Nimda.Amm.exe"

# Step 6: Follow TCP Stream
# Right-click packet > Follow > TCP Stream

# Step 7: Close TCP Stream window

# Step 8: Extract HTTP objects
# Menu: File > Export Objects > HTTP

# Step 9: Select the executable file
# Click on W32.Nimda.Amm.exe in the list

# Step 10: Save the file
# Click "Save As"
# Navigate to /home/analyst
# Click Save

# Step 11: Verify file was saved
cd /home/analyst
ls -l

# Step 12: Identify file type
file W32.Nimda.Amm.exe

# Expected output: PE32+ executable (console) x86-64, for MS Windows

# Next Steps for Analysis:
# 1. Move to isolated/sandboxed environment
# 2. Execute in controlled VM
# 3. Monitor behavior (network, file system, registry)
# 4. Upload to VirusTotal for analysis'''
        },
        {
            'title': 'Exploring DNS Traffic with Wireshark',
            'category': 'Network Analysis',
            'theory': '''Domain Name System (DNS) is a fundamental internet protocol that translates human-readable domain names into IP addresses.

DNS Components:
- Query: Request from client to DNS server
- Response: Answer from DNS server to client
- Default Port: UDP/TCP 53
- Record Types: A (IPv4), AAAA (IPv6), CNAME (alias), MX (mail)

DNS Process:
1. Client sends query to DNS server
2. DNS server performs recursive lookup if needed
3. Server returns response with IP address
4. Client uses IP to establish connection

Wireshark allows detailed analysis of DNS traffic including query types, response codes, and timing information.''',
            'steps': '''# Step 1: Start Wireshark
# Open Wireshark application

# Step 2: Select network interface
# Choose active interface with traffic

# Step 3: Clear DNS cache (Windows)
ipconfig /flushdns

# Step 3: Clear DNS cache (Linux - Systemd-Resolved)
systemctl status systemd-resolved.service
systemd-resolve --flush-caches
sudo systemctl restart systemd-resolved.service

# Step 3: Clear DNS cache (Linux - DNSMasq)
systemctl status dnsmasq.service
sudo systemctl restart dnsmasq.service

# Step 3: Clear DNS cache (macOS)
sudo killall -HUP mDNSResponder

# Step 4: Enter interactive nslookup mode
nslookup

# Step 5: Query a domain
www.cisco.com

# Step 6: Exit nslookup
exit

# Step 7: Stop Wireshark capture
# Click the red stop button

# Step 8: Filter for DNS traffic
# In filter box, enter: udp.port == 53

# Step 9: Analyze DNS Query packet
# Select packet with "Standard query"
# Expand: Ethernet II
# Expand: Internet Protocol Version 4
# Expand: User Datagram Protocol
# Expand: Domain Name System (query)

# Step 10: Note query details
# Source/Destination MAC addresses
# Source/Destination IP addresses
# Source/Destination ports (source: random, dest: 53)
# Query type and domain name

# Step 11: Analyze DNS Response packet
# Select corresponding response packet
# Expand: Domain Name System (response)
# Expand: Flags, Queries, Answers

# Step 12: Examine response details
# Check if recursive queries supported
# View CNAME and A records
# Note returned IP addresses'''
        },
        {
            'title': 'Configure Syslog Server on Linux',
            'category': 'Log Management',
            'theory': '''Rsyslog is a rocket-fast system for log processing commonly used for centralized logging. It allows remote systems to send logs to a central server for analysis and storage.

Key Concepts:
- Syslog Protocol: Standard for message logging (RFC 5424)
- UDP Port 514: Default syslog port
- Log Forwarding: Sending logs from clients to central server
- Templates: Define log format and storage location
- Rulesets: Process and route incoming logs

Benefits:
- Centralized log management
- Easier troubleshooting
- Better security monitoring
- Compliance requirements

Configuration involves both server-side (receiving logs) and client-side (sending logs) setup.''',
            'steps': '''# SERVER CONFIGURATION

# Step 1: Update system packages
apt update

# Step 2: Install rsyslog
apt install rsyslog

# Step 3: Edit rsyslog configuration
vi /etc/rsyslog.conf

# Step 4: Enable UDP log reception
# Add these lines:
module(load="imudp")

# Step 5: Create custom config file
vi /etc/rsyslog.d/00-custom.conf

# Step 6: Add template and ruleset
# Templates
template(name="ReceiveFormat" type="string" string="%msg:39:$%\\n")

# UDP ruleset mapping
input(type="imudp" port="514" ruleset="customRuleset")

# Custom ruleset (replace token with your own)
ruleset(name="customRuleset") {
    if ($msg contains 'your-custom-token-here') then {
        /var/log/cdn.log;ReceiveFormat
        stop
    }
}

# Step 7: Restart rsyslog
systemctl restart rsyslog

# Step 8: Verify logs are being received
tail -f /var/log/cdn.log

# TROUBLESHOOTING COMMANDS

# Check if rsyslog is running
systemctl status rsyslog

# Verify rsyslog is listening on port 514
netstat -na | grep :514

# Capture packets on port 514
tcpdump port 514

# CLIENT CONFIGURATION

# Step 9: Add loghost entry to /etc/hosts
vi /etc/hosts
# Add line (replace with your server IP):
10.10.10.1 server-syslog.domain.com server-syslog loghost

# Step 10: Edit client syslog.conf
vi /etc/syslog.conf

# Step 11: Configure log forwarding
*.debug @loghost
*.debug /var/log/messages

# Step 12: Restart syslog on client
/etc/init.d/syslog restart

# Step 13: Test configuration
# Generate test log message and verify on server'''
        },
        {
            'title': 'Install and Configure Splunk on Linux',
            'category': 'SIEM',
            'theory': '''Splunk is a powerful platform for searching, monitoring, and analyzing machine-generated data. It provides real-time insights into IT infrastructure and security events.

Key Features:
- Data Indexing: Fast searching across massive datasets
- Real-time Monitoring: Live dashboards and alerts
- Security Analytics: Threat detection and investigation
- Custom Dashboards: Visualize data meaningfully

Architecture:
- Forwarders: Collect data from sources
- Indexers: Store and index data
- Search Heads: User interface for queries

Default Port: 8000 (web interface)
Default Credentials: Set during installation

Splunk is widely used for SIEM (Security Information and Event Management) and log analysis.''',
            'steps': '''# METHOD 1: Install from RPM (Red Hat/CentOS)

# Step 1: Download Splunk RPM
wget -O splunk-8.0.0-1357bef0a7f6-linux-2.6-x86_64.rpm 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=8.0.0&product=splunk&filename=splunk-8.0.0-1357bef0a7f6-linux-2.6-x86_64.rpm&wget=true'

# Step 2: Create Splunk user and group
groupadd splunk
useradd -d /opt/splunk -m -g splunk splunk

# Step 3: Create installers directory
mkdir /opt/installers

# Step 4: Copy RPM to installers directory
cp splunk-8.0.0-1357bef0a7f6-linux-2.6-x86_64.rpm /opt/installers/

# Step 5: Change ownership
chown -R splunk: /opt/splunk/ /opt/installers

# Step 6: Switch to splunk user
su - splunk

# Step 7: Navigate to installers directory
cd /opt/installers

# Step 8: Install Splunk
rpm -i splunk-8.0.0-1357bef0a7f6-linux-2.6-x86_64.rpm

# Step 9: Start Splunk and accept license
/opt/splunk/bin/splunk start --accept-license

# Step 10: Enter administrator username
# When prompted, enter username

# Step 11: Set administrator password
# Password must contain at least 8 printable ASCII characters

# Step 12: Enable Splunk to start at boot
/opt/splunk/bin/splunk enable boot-start

# METHOD 2: Install from TAR file

# Step 1: Download TAR file
# Visit https://www.splunk.com/en_us/download.html

# Step 2: Extract TAR file
tar xvzf splunk-<version>-linux-<architecture>.tgz -C /opt

# Step 3: Navigate to Splunk directory
cd /opt/splunk

# Step 4: Start Splunk
./splunk start

# Step 5: Access Splunk Web Interface
# Open browser: http://localhost:8000
# Or: http://<hostname>:8000

# MANAGEMENT COMMANDS

# Start Splunk
sudo /opt/splunk/bin/splunk start

# Stop Splunk
sudo /opt/splunk/bin/splunk stop

# Check Splunk status
sudo /opt/splunk/bin/splunk status

# Restart Splunk
sudo /opt/splunk/bin/splunk restart'''
        },
        {
            'title': 'Install ELK Stack on RHEL',
            'category': 'Log Analytics',
            'theory': '''ELK Stack (Elasticsearch, Logstash, Kibana) is a powerful set of tools for centralized logging and log analysis.

Components:
- Elasticsearch: Search and analytics engine that stores logs
- Logstash: Server-side data processing pipeline
- Kibana: Visualization and exploration tool
- Beats: Lightweight data shippers (optional)

Architecture:
1. Beats/Logstash collect and process logs
2. Elasticsearch indexes and stores data
3. Kibana provides web interface for analysis

Requirements:
- Java JDK 21 or later
- 4GB+ RAM recommended
- Sufficient disk space for logs

The ELK stack is ideal for troubleshooting, monitoring, and security analytics across distributed systems.''',
            'steps': '''# Step 1: Update system
yum update

# Step 2: Download Java JDK 21
cd /opt
wget https://download.oracle.com/java/21/latest/jdk-21_linux-x64_bin.rpm

# Step 3: Install Java
rpm -Uvh jdk-21_linux-x64_bin.rpm

# Step 4: Verify Java installation
java -version

# ELASTICSEARCH INSTALLATION

# Step 5: Import Elasticsearch GPG key
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

# Step 6: Create Elasticsearch repository
vi /etc/yum.repos.d/elasticsearch.repo

# Add content:
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=0
autorefresh=1
type=rpm-md

# Step 7: Install Elasticsearch
yum install --enablerepo=elasticsearch elasticsearch

# Step 8: Start and enable Elasticsearch
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# Step 9: Configure firewall for Elasticsearch
firewall-cmd --add-port=9200/tcp
firewall-cmd --add-port=9200/tcp --permanent

# Step 10: Verify Elasticsearch is running
curl -X GET http://localhost:9200

# LOGSTASH INSTALLATION

# Step 11: Download Logstash
wget https://artifacts.elastic.co/downloads/logstash/logstash-7.6.1.rpm

# Step 12: Install Logstash
rpm -ivh logstash-7.6.1.rpm

# Step 13: Configure Logstash input (Filebeat)
vi /etc/logstash/conf.d/input.conf

# Add:
input {
    beats {
        client_inactivity_timeout => 600
        port => 5044
        ssl => true
        ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
        ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
    }
}

# Step 14: Configure Logstash filter
vi /etc/logstash/conf.d/filter.conf

# Add:
filter {
    if [type] == "syslog" {
        grok {
            match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\\[%{POSINT:syslog_pid}\\])?: %{GREEDYDATA:syslog_message}" }
        }
        date {
            match => [ "syslog_timestamp", "MMM d HH:mm:ss", "MMM dd HH:mm:ss" ]
        }
    }
}

# Step 15: Configure Logstash output
vi /etc/logstash/conf.d/output.conf

# Add:
output {
    elasticsearch {
        hosts => ["localhost:9200"]
        index => "syslog-%{+YYYY.MM.dd}"
    }
}

# Step 16: Start and enable Logstash
systemctl enable logstash
systemctl start logstash

# Step 17: Configure firewall for Logstash
firewall-cmd --add-port=5044/tcp --permanent
firewall-cmd --reload

# KIBANA INSTALLATION

# Step 18: Download Kibana
wget https://artifacts.elastic.co/downloads/kibana/kibana-7.6.1-x86_64.rpm

# Step 19: Install Kibana
rpm -ivh kibana-7.6.1-x86_64.rpm

# Step 20: Configure Kibana
vi /etc/kibana/kibana.yml

# Configure:
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]

# Step 21: Start and enable Kibana
systemctl enable kibana
systemctl start kibana

# Step 22: Access Kibana
# Open browser: http://<server-ip>:5601'''
        },
        {
            'title': 'Install Graylog on RHEL',
            'category': 'Log Management',
            'theory': '''Graylog is an industry-leading open-source log management solution for collecting, storing, indexing, and analyzing real-time data from various IT infrastructure components.

Architecture:
- Graylog Server: Main processing engine
- MongoDB: Stores configuration data
- Elasticsearch: Indexes and searches logs
- Web Interface: Browser-based management

Data Sources:
- Syslog (TCP, UDP, AMQP, Kafka)
- AWS logs, CloudTrail, FlowLogs
- Netflow (UDP)
- GELF (TCP, UDP, AMQP, Kafka)
- Beats and Logstash
- HTTP API (JSON Path)

Key Features:
- Real-time log processing
- Powerful search capabilities
- Alerting and notifications
- Customizable dashboards
- Role-based access control

Used by: Fiverr, CircleCI, CraftBase, BitPanda.''',
            'steps': '''# Step 1: Install EPEL repository
sudo dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

# Step 2: Install required packages
sudo dnf install -y pwgen wget curl perl-Digest-SHA

# INSTALL JAVA

# Step 3: Install OpenJDK 11
sudo dnf install java-11-openjdk java-11-openjdk-devel -y

# Step 4: Verify Java installation
java -version

# INSTALL ELASTICSEARCH

# Step 5: Create Elasticsearch repository
sudo vim /etc/yum.repos.d/elasticsearch.repo

# Add content:
[elasticsearch-7.x]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/oss-7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md

# Step 6: Install Elasticsearch OSS
sudo dnf install elasticsearch-oss

# Step 7: Configure Elasticsearch for Graylog
sudo vim /etc/elasticsearch/elasticsearch.yml

# Set cluster name:
cluster.name: graylog

# Step 8: Reload systemd and start Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service

# Step 9: Verify Elasticsearch is running
curl -X GET http://localhost:9200

# INSTALL MONGODB

# Step 10: Create MongoDB repository
sudo vim /etc/yum.repos.d/mongodb-org-4.repo

# Add content:
[mongodb-org-4]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/8/mongodb-org/4.4/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-4.4.asc

# Step 11: Install MongoDB
sudo dnf install mongodb-org

# Step 12: Start and enable MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# Step 13: Verify MongoDB version
mongo --version

# INSTALL GRAYLOG

# Step 14: Install Graylog repository
sudo rpm -Uvh https://packages.graylog2.org/repo/packages/graylog-4.2-repository_latest.rpm

# Step 15: Install Graylog server
sudo dnf install graylog-server

# Step 16: Verify Graylog installation
rpm -qi graylog-server

# CONFIGURE GRAYLOG

# Step 17: Generate password_secret
pwgen -N 1 -s 96

# Step 18: Generate root password hash
echo -n YourPasswordHere | shasum -a 256

# Step 19: Edit Graylog configuration
sudo vim /etc/graylog/server/server.conf

# Configure these parameters:
root_username = admin
root_password_sha2 = <hash from step 18>
password_secret = <secret from step 17>
http_bind_address = 0.0.0.0:9000
root_timezone = UTC

# Step 20: Start and enable Graylog
sudo systemctl start graylog-server.service
sudo systemctl enable graylog-server.service

# Step 21: Check Graylog logs
tail -f /var/log/graylog-server/server.log

# Step 22: Configure firewall
sudo firewall-cmd --add-port=9000/tcp --permanent
sudo firewall-cmd --reload

# Step 23: Access Graylog Web UI
# Open browser: http://<server-ip>:9000
# Login with username: admin
# Password: <password used in step 18>'''
        },
        {
            'title': 'Normalize Log Timestamps with AWK',
            'category': 'Log Processing',
            'theory': '''Log normalization converts data from various sources into a consistent format. This lab focuses on timestamp normalization using AWK, a powerful text processing language.

Timestamp Formats:
- Unix Epoch: Seconds since January 1, 1970 (e.g., 1498656439)
- Human Readable: Separate values for year, month, day, etc.

AWK Fundamentals:
- Field Separator (FS): Character that delimits columns
- Built-in Functions: strftime(), gsub()
- Actions: Operations performed on each line
- Variables: $1, $2, $3 represent column values

Benefits:
- Easier analysis with human-readable dates
- Consistent format across different log sources
- Facilitates correlation between events
- Better for reporting and visualization

This technique is essential for security analysts working with logs from multiple sources.''',
            'steps': '''# PART 1: Basic Timestamp Conversion

# Step 1: Navigate to lab files
cd /home/analyst/lab.support.files/

# Step 2: List available files
ls -l

# Step 3: View sample log file
cat applicationX_in_epoch.log

# Step 4: Convert Epoch to Human Readable
awk 'BEGIN {FS=OFS="|"} {$3=strftime("%c",$3)} {print}' applicationX_in_epoch.log

# Explanation:
# BEGIN {FS=OFS="|"} - Set field separator to pipe character
# {$3=strftime("%c",$3)} - Convert column 3 using strftime
# {print} - Print the modified line

# Step 5: Remove empty lines from file
nano applicationX_in_epoch.log
# Delete the last empty line, save and exit

# Step 6: Run script again to verify
awk 'BEGIN {FS=OFS="|"} {$3=strftime("%c",$3)} {print}' applicationX_in_epoch.log

# Step 7: Save output to new file
awk 'BEGIN {FS=OFS="|"} {$3=strftime("%c",$3)} {print}' applicationX_in_epoch.log > applicationX_in_human.log

# Step 8: View converted file
cat applicationX_in_human.log

# PART 2: Apache Log Conversion

# Step 9: View Apache log file
cat apache_in_epoch.log

# Step 10: First attempt (will fail due to brackets)
awk 'BEGIN {FS=OFS=" "} {$4=strftime("%c",$4)} {print}' apache_in_epoch.log

# Step 11: Improved script with bracket removal
awk 'BEGIN {FS=OFS=" "} {gsub(/\\[|\\]/,"",$4)} {print} {$4=strftime("%c",$4)} {print}' apache_in_epoch.log

# Explanation of gsub():
# gsub(/\\[|\\]/,"",$4) - Global substitution
# /\\[|\\]/ - Match '[' OR ']' (escaped)
# "" - Replace with empty string
# $4 - Apply to column 4 only

# Step 12: Save Apache converted logs
awk 'BEGIN {FS=OFS=" "} {gsub(/\\[|\\]/,"",$4)} {$4=strftime("%c",$4)} {print}' apache_in_epoch.log > apache_in_human.log

# Step 13: View converted Apache logs
cat apache_in_human.log

# ADVANCED: Custom Time Formats

# Step 14: Convert to specific format (YYYY-MM-DD HH:MM:SS)
awk 'BEGIN {FS=OFS="|"} {$3=strftime("%Y-%m-%d %H:%M:%S",$3)} {print}' applicationX_in_epoch.log

# Step 15: Convert to date only
awk 'BEGIN {FS=OFS="|"} {$3=strftime("%Y-%m-%d",$3)} {print}' applicationX_in_epoch.log

# TROUBLESHOOTING

# If script shows wrong timezone, set TZ variable:
export TZ='America/New_York'
awk 'BEGIN {FS=OFS="|"} {$3=strftime("%c",$3)} {print}' applicationX_in_epoch.log

# List available timezones:
timedatectl list-timezones'''
        }
    ]
    
    for practical in practicals_data:
        cursor.execute('''
            INSERT INTO practicals (title, category, theory, steps)
            VALUES (?, ?, ?, ?)
        ''', (practical['title'], practical['category'], practical['theory'], practical['steps']))
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Home page with list of practicals"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, category FROM practicals ORDER BY id')
    practicals = cursor.fetchall()
    conn.close()
    return render_template('index.html', practicals=practicals)

@app.route('/practical/<int:practical_id>')
def practical(practical_id):
    """Individual practical page"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM practicals WHERE id = ?', (practical_id,))
    practical = cursor.fetchone()
    conn.close()
    
    if practical is None:
        return "Practical not found", 404
    
    return render_template('practical.html', practical=practical)

@app.route('/api/practicals')
def get_all_practicals():
    """API endpoint to get all practicals"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, category FROM practicals ORDER BY id')
    practicals = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(p) for p in practicals])

@app.route('/api/practical/<int:practical_id>')
def get_practical(practical_id):
    """API endpoint to get a specific practical"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM practicals WHERE id = ?', (practical_id,))
    practical = cursor.fetchone()
    conn.close()
    
    if practical is None:
        return jsonify({'error': 'Practical not found'}), 404
    
    return jsonify(dict(practical))

# File download routes
@app.route('/download/sopr-docx')
def download_sopr_docx():
    """Download SOPR.docx file from static/downloads"""
    try:
        file_path = os.path.join(DOWNLOADS_DIR, 'SOPR.docx')
        
        if not os.path.exists(file_path):
            return jsonify({
                'error': 'SOPR.docx file not found',
                'tip': 'Make sure SOPR.docx is in the static/downloads/ directory'
            }), 404
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name='PVRdataset.docx',
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
    except Exception as e:
        return jsonify({'error': f'Download error: {str(e)}'}), 500

@app.route('/download/sopr-pdf')
def download_sopr_pdf():
    """Download SOPR1.pdf file from static/downloads"""
    try:
        # Check for PDF files in downloads directory
        pdf_names = ['SOPR1.pdf', 'SOPR.pdf', 'Kraggle.pdf']
        
        for pdf_name in pdf_names:
            pdf_path = os.path.join(DOWNLOADS_DIR, pdf_name)
            if os.path.exists(pdf_path):
                return send_file(
                    pdf_path,
                    as_attachment=True,
                    download_name='Kraggle.pdf',
                    mimetype='application/pdf'
                )
        
        return jsonify({
            'error': 'PDF file not found',
            'tip': 'Place a PDF file (SOPR1.pdf or SOPR.pdf) in the static/downloads/ directory',
            'alternative': 'You can convert SOPR.docx to PDF and upload it to static/downloads/'
        }), 404
    except Exception as e:
        return jsonify({'error': f'Download error: {str(e)}'}), 500

# Alternative: Direct static file serving (for public CDN-style access)
@app.route('/files/<filename>')
def serve_file(filename):
    """Serve files directly from static/downloads directory"""
    try:
        return send_from_directory(DOWNLOADS_DIR, filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': f'File {filename} not found'}), 404

@app.route('/debug/files')
def debug_files():
    """Debug route to check available files"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    downloads_files = os.listdir(DOWNLOADS_DIR) if os.path.exists(DOWNLOADS_DIR) else []
    
    files_info = {
        'base_directory': base_dir,
        'downloads_directory': DOWNLOADS_DIR,
        'downloads_exists': os.path.exists(DOWNLOADS_DIR),
        'files_in_downloads': downloads_files,
        'sopr_docx_exists': os.path.exists(os.path.join(DOWNLOADS_DIR, 'SOPR.docx')),
        'sopr_pdf_exists': os.path.exists(os.path.join(DOWNLOADS_DIR, 'SOPR1.pdf')),
        'sopr_docx_path': os.path.join(DOWNLOADS_DIR, 'SOPR.docx'),
        'available_downloads': {
            'docx': os.path.exists(os.path.join(DOWNLOADS_DIR, 'SOPR.docx')),
            'pdf': any(os.path.exists(os.path.join(DOWNLOADS_DIR, name)) 
                      for name in ['SOPR1.pdf', 'SOPR.pdf'])
        }
    }
    return jsonify(files_info)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
