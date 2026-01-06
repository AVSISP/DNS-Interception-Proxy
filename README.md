# DNS Proxy - Dual Stack IPv4/IPv6

High-performance asynchronous DNS proxy that intercepts DNS queries from specified clients (via ipset) and forwards them to a backend DNS server while maintaining the original destination IP as the source address in responses.

## Features

- 🚀 Asynchronous event-driven architecture (epoll)
- 🌐 Full IPv4 and IPv6 client support
- ⚡ High throughput with thread pool design
- 🎯 Selective interception using ipset
- 🔄 Automatic timeout handling
- 📊 Query tracking and drop monitoring

## Requirements

- Linux kernel with netfilter support
- `libnetfilter-queue-dev`
- `ipset`
- `iptables` and `ip6tables`
- GCC compiler

### Install Dependencies

```bash
# Debian/Ubuntu
apt-get update
apt-get install -y libnetfilter-queue-dev ipset iptables build-essential

# RHEL/CentOS
yum install -y libnetfilter_queue-devel ipset iptables gcc make
```

## Configuration

### 1. Set Backend DNS Server

Edit `dns.c` and change the DNS server IP address:

```c
#define DNS_SERVER "1.1.1.1"  // Change this to your DNS server
#define DNS_PORT 53
```

### 2. Compile

```bash
gcc -o dns dns.c -lnetfilter_queue -lpthread -O2
```

### 3. Install Binary

```bash
sudo install -m 755 dns /usr/local/bin/dns-proxy
```

## IPSet Configuration

### Create IPSets

```bash
# Create IPv4 ipset
ipset create mydns4 hash:ip family inet

# Create IPv6 ipset
ipset create mydns6 hash:ip family inet6
```

### Add IPs to IPSets

```bash
# Add IPv4 addresses
ipset add mydns4 192.168.1.100
ipset add mydns4 10.0.0.0/24

# Add IPv6 addresses
ipset add mydns6 2001:db8::1
ipset add mydns6 fd00::/64
```

### List IPSets

```bash
ipset list mydns4
ipset list mydns6
```

### Save IPSets (persist across reboots)

```bash
# Save to file
ipset save > /etc/ipset.conf

# Restore on boot (add to /etc/rc.local or systemd)
ipset restore < /etc/ipset.conf
```

## Firewall Rules

### Apply iptables Rules

```bash
# IPv4 - Intercept DNS queries from mydns4 clients
iptables -t mangle -A PREROUTING -p udp --dport 53 -m set --match-set mydns4 src -j NFQUEUE --queue-num 53

# IPv6 - Intercept DNS queries from mydns6 clients
ip6tables -t mangle -A PREROUTING -p udp --dport 53 -m set --match-set mydns6 src -j NFQUEUE --queue-num 53
```

### Make Rules Persistent

#### Option 1: Using iptables-persistent (Debian/Ubuntu)

```bash
apt-get install iptables-persistent
netfilter-persistent save
```

#### Option 2: Using systemd service

Create `/etc/systemd/system/dns-proxy-firewall.service`:

```ini
[Unit]
Description=DNS Proxy Firewall Rules
Before=dns-proxy.service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'ipset restore < /etc/ipset.conf || true'
ExecStart=/sbin/iptables -t mangle -A PREROUTING -p udp --dport 53 -m set --match-set mydns4 src -j NFQUEUE --queue-num 53
ExecStart=/sbin/ip6tables -t mangle -A PREROUTING -p udp --dport 53 -m set --match-set mydns6 src -j NFQUEUE --queue-num 53
ExecStop=/sbin/iptables -t mangle -D PREROUTING -p udp --dport 53 -m set --match-set mydns4 src -j NFQUEUE --queue-num 53
ExecStop=/sbin/ip6tables -t mangle -D PREROUTING -p udp --dport 53 -m set --match-set mydns6 src -j NFQUEUE --queue-num 53

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
systemctl enable dns-proxy-firewall.service
systemctl start dns-proxy-firewall.service
```

## Systemd Service

Create `/etc/systemd/system/dns-proxy.service`:

```ini
[Unit]
Description=DNS Proxy - Dual Stack IPv4/IPv6
After=network.target dns-proxy-firewall.service
Wants=dns-proxy-firewall.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dns-proxy
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Enable and Start Service

```bash
# Reload systemd
systemctl daemon-reload

# Enable auto-start at boot
systemctl enable dns-proxy.service

# Start the service
systemctl start dns-proxy.service

# Check status
systemctl status dns-proxy.service

# View logs
journalctl -u dns-proxy.service -f
```

### Service Management

```bash
# Restart service
systemctl restart dns-proxy.service

# Stop service
systemctl stop dns-proxy.service

# Disable auto-start
systemctl disable dns-proxy.service
```

## Complete Setup Example

```bash
# 1. Install dependencies
apt-get update && apt-get install -y libnetfilter-queue-dev ipset iptables build-essential

# 2. Compile
gcc -o dns dns.c -lnetfilter_queue -lpthread -O2

# 3. Install binary
sudo install -m 755 dns /usr/local/bin/dns-proxy

# 4. Create ipsets
ipset create mydns4 hash:ip family inet
ipset create mydns6 hash:ip family inet6

# 5. Add some IPs
ipset add mydns4 192.168.1.0/24
ipset add mydns6 2001:db8::/64

# 6. Save ipsets
ipset save > /etc/ipset.conf

# 7. Create firewall service
cat > /etc/systemd/system/dns-proxy-firewall.service << 'EOF'
[Unit]
Description=DNS Proxy Firewall Rules
Before=dns-proxy.service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'ipset restore < /etc/ipset.conf || true'
ExecStart=/sbin/iptables -t mangle -A PREROUTING -p udp --dport 53 -m set --match-set mydns4 src -j NFQUEUE --queue-num 53
ExecStart=/sbin/ip6tables -t mangle -A PREROUTING -p udp --dport 53 -m set --match-set mydns6 src -j NFQUEUE --queue-num 53
ExecStop=/sbin/iptables -t mangle -D PREROUTING -p udp --dport 53 -m set --match-set mydns4 src -j NFQUEUE --queue-num 53
ExecStop=/sbin/ip6tables -t mangle -D PREROUTING -p udp --dport 53 -m set --match-set mydns6 src -j NFQUEUE --queue-num 53

[Install]
WantedBy=multi-user.target
EOF

# 8. Create dns-proxy service
cat > /etc/systemd/system/dns-proxy.service << 'EOF'
[Unit]
Description=DNS Proxy - Dual Stack IPv4/IPv6
After=network.target dns-proxy-firewall.service
Wants=dns-proxy-firewall.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dns-proxy
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 9. Enable and start services
systemctl daemon-reload
systemctl enable dns-proxy-firewall.service dns-proxy.service
systemctl start dns-proxy-firewall.service dns-proxy.service

# 10. Verify
systemctl status dns-proxy.service
journalctl -u dns-proxy.service -f
```

## Monitoring

### Check Service Status

```bash
systemctl status dns-proxy.service
```

### View Real-time Logs

```bash
journalctl -u dns-proxy.service -f
```

### Check Queue Statistics

```bash
# Check NFQUEUE stats
cat /proc/net/netfilter/nfnetlink_queue
```

### Verify IPSet Membership

```bash
# Check if an IP is in the set
ipset test mydns4 192.168.1.100
ipset test mydns6 2001:db8::1
```

## Troubleshooting

### Service won't start

```bash
# Check for errors
journalctl -u dns-proxy.service -n 50

# Verify binary exists
ls -l /usr/local/bin/dns-proxy

# Check permissions
sudo /usr/local/bin/dns-proxy
```

### No DNS responses

```bash
# Verify iptables rules are active
iptables -t mangle -L PREROUTING -n -v
ip6tables -t mangle -L PREROUTING -n -v

# Check if packets are hitting the queue
cat /proc/net/netfilter/nfnetlink_queue

# Verify ipsets exist
ipset list
```

### IPv6 not working

```bash
# Check IPv6 is enabled
sysctl net.ipv6.conf.all.disable_ipv6

# Verify IPv6 firewall rules
ip6tables -t mangle -L PREROUTING -n -v

# Test IPv6 connectivity
ping6 2001:4860:4860::8888
```

## Performance Tuning

Adjust these values in `dns.c` before compiling:

```c
#define MAX_PENDING 1000        // Maximum concurrent queries
#define DNS_TIMEOUT_MS 300      // Query timeout in milliseconds
#define THREAD_POOL_SIZE 20     // Event loop thread count
```

## Security Considerations

- This proxy requires **root privileges** to use raw sockets and NFQUEUE
- Only intercepts DNS queries from IPs in the ipset lists
- Responses are spoofed to appear from the original destination IP
- Enable `NoNewPrivileges=true` in systemd if not using raw sockets

## License

This project is provided as-is for educational and infrastructure purposes.

## Architecture

```
Client (IPv4/IPv6) → iptables/ip6tables → NFQUEUE(53) → dns-proxy
                                                            ↓
                                                    Backend DNS Server
                                                            ↓
                                                    dns-proxy → Client
                                                    (spoofed source)
```

The proxy:
1. Intercepts DNS queries via NFQUEUE
2. Forwards them to the backend DNS server (IPv4)
3. Receives responses
4. Sends spoofed responses back to clients with original destination IP as source
