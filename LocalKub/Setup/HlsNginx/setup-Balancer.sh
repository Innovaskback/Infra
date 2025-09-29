#!/bin/bash

# Nginx Load Balancer Setup Script - Enhanced Version
# Description: Automated installation and configuration of Nginx Load Balancer (IP-only optimized)
# Author: System Administrator
# Date: $(date +%Y-%m-%d)

set -e  # Exit on any error

# Configuration file path
CONFIG_FILE="${CONFIG_FILE:-/etc/nginx-lb/config.env}"

# Default configuration
SERVER_IP=$(curl -s ifconfig.me)
DEFAULT_LB_IP=$SERVER_IP
echo "Server IP: $DEFAULT_LB_IP"
DEFAULT_USE_SSL="false"  # Changed to false for IP-only setup
DEFAULT_SSL_TYPE="none"   # Options: none, self-signed, internal-ca

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR $(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING $(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO $(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

# Load configuration function
load_configuration() {
    log "Loading configuration..."
    
    # Create config directory if not exists
    sudo mkdir -p /etc/nginx-lb
    
    # Load config file if exists
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log "Configuration loaded from: $CONFIG_FILE"
    else
        log "Config file not found, creating default configuration..."
        create_default_config
    fi
    
    # Set defaults if variables not set
    USE_SSL="${USE_SSL:-$DEFAULT_USE_SSL}"
    SSL_TYPE="${SSL_TYPE:-$DEFAULT_SSL_TYPE}"
    
    # Validate IP address
    if ! validate_ip "$DEFAULT_LB_IP"; then
        error "Invalid IP address: $DEFAULT_LB_IP"
        exit 1
    fi
    
    log "Load Balancer IP: $DEFAULT_LB_IP"
    log "SSL Enabled: $USE_SSL"
    log "SSL Type: $SSL_TYPE"
}

# Create default configuration file
create_default_config() {
    sudo tee "$CONFIG_FILE" > /dev/null << EOF
# Nginx Load Balancer Configuration
# Edit this file to customize your setup

# Load Balancer IP Address

# SSL Configuration
USE_SSL="$DEFAULT_USE_SSL"
SSL_TYPE="$DEFAULT_SSL_TYPE"

# Server Arrays - Edit these IPs according to your infrastructure
KUBERNETES_IPS=("64.20.63.4" "64.20.63.5" "162.250.127.91")
STORAGE_IPS=("162.250.127.91" "69.10.55.221")
BETAKUBERNETES_IPS=("64.20.63.4" "69.10.55.226")
WEBSOCKET_IPS=("69.10.55.226")

# Health Check Settings
HEALTH_CHECK_ENABLED="true"
HEALTH_CHECK_INTERVAL="30"

# Monitoring Settings
ENABLE_METRICS="true"
METRICS_PORT="8080"

# Performance Settings
WORKER_PROCESSES="auto"
WORKER_CONNECTIONS="4096"
EOF
    
    log "Default configuration created at: $CONFIG_FILE"
    warning "Please edit $CONFIG_FILE to match your server setup"
}

# IP validation function
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if [[ $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Server connectivity check
check_server_connectivity() {
    local server=$1
    local port=$2
    local timeout=${3:-5}
    
    log "Checking connectivity to $server:$port..."
    
    if timeout "$timeout" bash -c "echo >/dev/tcp/$server/$port" 2>/dev/null; then
        log "✓ Server $server:$port is reachable"
        return 0
    else
        warning "✗ Server $server:$port is not reachable"
        return 1
    fi
}

# Validate all servers connectivity
validate_servers() {
    log "Validating server connectivity..."
    local failed_servers=()
    
    # Load server arrays from config
    source "$CONFIG_FILE"
    
    # Check kubernetes servers
    for ip in "${KUBERNETES_IPS[@]}"; do
        if ! check_server_connectivity "$ip" "80" 3; then
            failed_servers+=("$ip:80")
        fi
    done
    
    # Check storage servers
    for ip in "${STORAGE_IPS[@]}"; do
        if ! check_server_connectivity "$ip" "8080" 3; then
            failed_servers+=("$ip:8080")
        fi
    done
    
    if [[ ${#failed_servers[@]} -gt 0 ]]; then
        warning "Some servers are not reachable:"
        for server in "${failed_servers[@]}"; do
            warning "  - $server"
        done
        warning "Load balancer will still be configured, but these servers may not respond"
        
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error "Setup cancelled by user"
            exit 1
        fi
    else
        log "All servers are reachable"
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
       error "This script should not be run as root. Please run as a user with sudo privileges."
       exit 1
    fi
    
    # Check sudo privileges
    if ! sudo -n true 2>/dev/null; then
        error "This script requires sudo privileges. Please ensure your user can run sudo commands."
        exit 1
    fi
    
    # Check required commands
    local required_commands=("curl" "openssl" "systemctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command '$cmd' not found"
            exit 1
        fi
    done
    
    log "Prerequisites check passed"
}

# SSL setup function (optimized for IP-only)
setup_ssl_configuration() {
    case "$SSL_TYPE" in
        "none")
            log "Skipping SSL configuration - HTTP only setup"
            return 0
            ;;
        "internal-ca")
            setup_internal_ca_ssl
            ;;
        "self-signed"|*)
            if [[ "$USE_SSL" == "true" ]]; then
                setup_self_signed_ssl
            else
                log "SSL disabled in configuration"
                return 0
            fi
            ;;
    esac
}

# Self-signed SSL for IP (with warnings)
setup_self_signed_ssl() {
    log "Setting up self-signed SSL certificate for IP: $DEFAULT_LB_IP"
    
    warning "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    warning "⚠️  IMPORTANT SSL NOTICE:"
    warning "   - Browsers will show 'Not Secure' warnings"
    warning "   - Certificate is for IP address, not domain"
    warning "   - Consider using HTTP-only for internal networks"
    warning "   - For production, use proper domain with valid certificate"
    warning "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Create enhanced certificate with SAN for IP
    cat > /tmp/ssl.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = EG
ST = Cairo
L = Cairo
O = Load Balancer
OU = Infrastructure
CN = $DEFAULT_LB_IP

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = $DEFAULT_LB_IP
IP.2 = 127.0.0.1
DNS.1 = localhost
EOF

    # Generate certificate with enhanced configuration
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/server.key \
        -out /etc/nginx/ssl/server.crt \
        -config /tmp/ssl.conf
    
    sudo rm /tmp/ssl.conf
    
    # Set proper permissions
    sudo chmod 600 /etc/nginx/ssl/server.key
    sudo chmod 644 /etc/nginx/ssl/server.crt
    sudo chown root:root /etc/nginx/ssl/server.*
    
    log "Self-signed SSL certificate created successfully"
}

# Internal CA SSL (for organizations with internal CA)
setup_internal_ca_ssl() {
    log "Setting up internal CA SSL configuration..."
    warning "Internal CA setup requires manual certificate installation"
    warning "This setup assumes you have an internal Certificate Authority"
    
    # Create CSR for internal CA signing
    sudo openssl req -new -newkey rsa:2048 -nodes \
        -keyout /etc/nginx/ssl/server.key \
        -out /tmp/server.csr \
        -subj "/C=EG/ST=Cairo/L=Cairo/O=LoadBalancer/CN=$DEFAULT_LB_IP"
    
    warning "Certificate Signing Request created at: /tmp/server.csr"
    warning "Please sign this CSR with your internal CA and place the certificate at: /etc/nginx/ssl/server.crt"
    warning "Setup will continue assuming certificate will be provided manually"
}

# Generate upstream configuration with connectivity validation
generate_upstream_config() {
    log "Generating upstream configuration with server validation..."
    
    # Load server arrays from config
    source "$CONFIG_FILE"
    
    # Function to generate upstream servers with validation
    generate_upstream_servers() {
        local server_type=$1
        local port=$2
        local weight=${3:-2}
        local max_fails=${4:-3}
        local fail_timeout=${5:-30s}
        
        case $server_type in
            "kubernetes")
                local -n ip_array=KUBERNETES_IPS
                ;;
            "storage")
                local -n ip_array=STORAGE_IPS
                ;;
            "betakubernetes")
                local -n ip_array=BETAKUBERNETES_IPS
                ;;
            "websocket")
                local -n ip_array=WEBSOCKET_IPS
                ;;
        esac
        
        local servers=""
        local active_servers=0
        
        for ip in "${ip_array[@]}"; do
            # Add server regardless of connectivity for configuration
            servers+="    server ${ip}:${port} weight=${weight} max_fails=${max_fails} fail_timeout=${fail_timeout};\n"
            
            # Check connectivity for information
            if check_server_connectivity "$ip" "$port" 2 >/dev/null 2>&1; then
                ((active_servers++))
            fi
        done
        
        # Add comment about active servers
        servers="    # Active servers: ${active_servers}/${#ip_array[@]}\n${servers}"
        
        echo -e "$servers"
    }
    
    # Generate upstream configuration file
    cat > /tmp/upstream.conf << EOF
# Upstream server groups configuration - Generated dynamically
# Load Balancer IP: $DEFAULT_LB_IP
# Generation Time: $(date)

# Main kubernetes application servers
upstream kubernetes_servers {
    least_conn;
    
$(generate_upstream_servers "kubernetes" "80" "3" "3" "30s")
    
    # Connection pooling for performance
    keepalive 32;
    keepalive_requests 100;
    keepalive_timeout 60s;
}

# Storage/Media servers for static content
upstream storage_servers {
    # Round-robin distribution for even load
    
$(generate_upstream_servers "storage" "8080" "2" "2" "20s")
    
    # Connection pooling optimized for large files
    keepalive 16;
    keepalive_requests 50;
    keepalive_timeout 120s;
}

# Beta kubernetes servers for API endpoints
upstream betakubernetes_servers {
    least_conn;
    
$(generate_upstream_servers "betakubernetes" "3000" "2" "2" "15s")
    
    # Connection pooling for API requests
    keepalive 64;
    keepalive_requests 200;
    keepalive_timeout 30s;
}

# WebSocket servers with session persistence
upstream websocket_servers {
    ip_hash;  # Maintain session persistence for WebSocket
    
$(generate_upstream_servers "websocket" "8081" "1" "2" "10s")
    
    # Connection settings for WebSocket
    keepalive 32;
    keepalive_timeout 60s;
}
EOF

    # Copy configuration to nginx directory
    sudo cp /tmp/upstream.conf /etc/nginx/conf.d/upstream.conf
    sudo rm /tmp/upstream.conf
    
    log "Upstream configuration generated successfully"
}

# Create optimized Nginx configuration for IP-only setup
create_nginx_main_config() {
    log "Creating optimized Nginx main configuration..."
    
    sudo tee /etc/nginx/nginx.conf > /dev/null << EOF
user www-data;
worker_processes ${WORKER_PROCESSES:-auto};
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

# Worker limits optimized for load balancing
worker_rlimit_nofile 65535;

events {
    worker_connections ${WORKER_CONNECTIONS:-4096};
    multi_accept on;
    use epoll;
}

http {
    # Basic settings optimized for proxy operations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 100;
    types_hash_max_size 2048;
    server_tokens off;
    client_max_body_size 100M;
    
    # Buffer sizes optimized for load balancing
    client_body_buffer_size 256k;
    client_header_buffer_size 4k;
    large_client_header_buffers 4 32k;
    proxy_buffer_size 16k;
    proxy_buffers 32 16k;
    proxy_busy_buffers_size 64k;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Enhanced logging with upstream information
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for" '
                    'rt=\$request_time uct="\$upstream_connect_time" '
                    'uht="\$upstream_header_time" urt="\$upstream_response_time" '
                    'us="\$upstream_status" ua="\$upstream_addr"';
    
    access_log /var/log/nginx/access.log main buffer=32k flush=5s;
    
    # Gzip compression optimized
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_types
        application/atom+xml
        application/javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rss+xml
        application/vnd.geo+json
        application/vnd.ms-fontobject
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        image/bmp
        image/svg+xml
        image/x-icon
        text/cache-manifest
        text/css
        text/plain
        text/vcard
        text/vnd.rim.location.xloc
        text/vtt
        text/x-component
        text/x-cross-domain-policy;
    
    # Rate limiting zones
    limit_req_zone \$binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=api:10m rate=30r/s;
    limit_req_zone \$binary_remote_addr zone=upload:10m rate=5r/s;
    limit_conn_zone \$binary_remote_addr zone=addr:10m;
    
    # Proxy cache settings
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=cache_zone:10m 
                     max_size=1g inactive=60m use_temp_path=off;
    
    # Include configurations
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
}

# Create load balancer site configuration
create_loadbalancer_config() {
    log "Creating load balancer site configuration..."
    
    local ssl_config=""
    local ssl_server=""
    
    # Generate SSL configuration if enabled
    if [[ "$USE_SSL" == "true" && "$SSL_TYPE" != "none" ]]; then
        ssl_server="
# HTTPS Server
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name $DEFAULT_LB_IP;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    
    # Security headers
    add_header Strict-Transport-Security \"max-age=31536000\" always;
    add_header X-Frame-Options \"SAMEORIGIN\" always;
    add_header X-Content-Type-Options \"nosniff\" always;
    add_header X-XSS-Protection \"1; mode=block\" always;
    
    # Include common configuration
    include /etc/nginx/snippets/loadbalancer-common.conf;
}"
    fi
    
    # Create the main server configuration
    sudo tee /etc/nginx/sites-available/loadbalancer > /dev/null << EOF
# Load Balancer Configuration for IP: $DEFAULT_LB_IP
# Generated: $(date)
# SSL Enabled: $USE_SSL

# HTTP Server
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DEFAULT_LB_IP _;
    
    # Logging
    access_log /var/log/nginx/lb_access.log main;
    error_log /var/log/nginx/lb_error.log warn;
    
    # Basic security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Include common configuration
    include /etc/nginx/snippets/loadbalancer-common.conf;
}

$ssl_server
EOF
    
    # Create common configuration snippet
    create_common_config
}

# Create common configuration snippet
create_common_config() {
    log "Creating common configuration snippet..."
    
    sudo mkdir -p /etc/nginx/snippets
    
    sudo tee /etc/nginx/snippets/loadbalancer-common.conf > /dev/null << 'EOF'
# Common Load Balancer Configuration

# Rate limiting
limit_req zone=general burst=20 nodelay;
limit_conn addr 50;

# Custom error pages
error_page 404 /404.html;
error_page 500 502 503 504 /50x.html;

location = /404.html {
    internal;
    default_type text/html;
    return 404 '<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>Load Balancer</center></body></html>';
}

location = /50x.html {
    internal;
    default_type text/html;
    return 500 '<html><head><title>Service Temporarily Unavailable</title></head><body><center><h1>Service Temporarily Unavailable</h1></center><hr><center>Load Balancer - Please try again later</center></body></html>';
}

# Health check endpoint
location /health {
    access_log off;
    return 200 "Load Balancer Status: OK\nIP: $server_name\nTime: $time_local\n";
    add_header Content-Type text/plain;
}

# Detailed health check
location /health/detailed {
    access_log off;
    default_type application/json;
    return 200 '{"status":"healthy","ip":"$server_name","time":"$time_iso8601","connections":{"active":"$connections_active","reading":"$connections_reading","writing":"$connections_writing","waiting":"$connections_waiting"}}';
}

# Storage/Media files routing
location ~ ^/(uploads|media|static|storage)/ {
    limit_req zone=upload burst=10 nodelay;
    
    proxy_pass http://storage_servers;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # Cache settings for static content
    proxy_cache cache_zone;
    proxy_cache_valid 200 302 1h;
    proxy_cache_valid 404 1m;
    proxy_cache_bypass $http_cache_control;
    add_header X-Cache-Status $upstream_cache_status;
    
    # Extended timeout for large files
    proxy_connect_timeout 30s;
    proxy_send_timeout 90s;
    proxy_read_timeout 90s;
    
    # Large file handling
    proxy_buffering on;
    proxy_buffer_size 8k;
    proxy_buffers 32 8k;
    proxy_busy_buffers_size 64k;
    client_body_timeout 60s;
    client_max_body_size 100M;
    
    expires 30d;
    add_header Cache-Control "public, immutable";
}

# API routing
location /beta/ {
    limit_req zone=api burst=50 nodelay;
    
    proxy_pass http://betakubernetes_servers;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Request-ID $request_id;
    
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    
    # API timeouts
    proxy_connect_timeout 10s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;
    
    # No caching for API
    proxy_cache_bypass 1;
    proxy_no_cache 1;
    
    # CORS headers
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
    
    if ($request_method = OPTIONS) {
        return 204;
    }
}

# WebSocket support
location /ws/ {
    proxy_pass http://websocket_servers;
    
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # WebSocket timeouts
    proxy_connect_timeout 7d;
    proxy_send_timeout 7d;
    proxy_read_timeout 7d;
    
    proxy_buffering off;
}

# Main application routing
location / {
    proxy_pass http://kubernetes_servers;
    
    # Essential headers
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Request-ID $request_id;
    
    # Handle redirects properly
    proxy_redirect ~^https?://[^/]+(.*)$ $scheme://$http_host$1;
    
    # Connection settings
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    
    # Timeouts
    proxy_connect_timeout 30s;
    proxy_send_timeout 30s;
    proxy_read_timeout 60s;
    
    # Buffer settings
    proxy_buffering on;
    proxy_buffer_size 8k;
    proxy_buffers 16 8k;
    proxy_busy_buffers_size 32k;
    
    # Handle upstream failures gracefully
    proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
    proxy_next_upstream_tries 3;
    proxy_next_upstream_timeout 10s;
    
    # Optional caching for GET requests
    proxy_cache cache_zone;
    proxy_cache_methods GET HEAD;
    proxy_cache_valid 200 302 10m;
    proxy_cache_valid 404 1m;
    proxy_cache_bypass $http_cache_control $cookie_session;
    proxy_no_cache $http_cache_control $cookie_session;
    add_header X-Cache-Status $upstream_cache_status;
}

# Static files optimization
location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|webp|mp4|webm)$ {
    proxy_pass http://kubernetes_servers;
    
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    proxy_redirect ~^https?://[^/]+(.*)$ $scheme://$http_host$1;
    
    # Aggressive caching for static assets
    proxy_cache cache_zone;
    proxy_cache_valid 200 302 7d;
    proxy_cache_valid 404 1m;
    add_header X-Cache-Status $upstream_cache_status;
    
    expires 7d;
    add_header Cache-Control "public, immutable";
    
    gzip_static on;
}

# Block malicious requests
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

location ~ \.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)|~ {
    deny all;
    access_log off;
    log_not_found off;
}
EOF
}

# Create monitoring configuration
create_monitoring_config() {
    if [[ "$ENABLE_METRICS" != "true" ]]; then
        log "Monitoring disabled in configuration"
        return 0
    fi
    
    log "Creating monitoring configuration..."
    
    sudo tee /etc/nginx/conf.d/monitoring.conf > /dev/null << EOF
# Monitoring Configuration
server {
    listen 127.0.0.1:${METRICS_PORT:-8080};
    listen [::1]:${METRICS_PORT:-8080};
    server_name localhost;
    
    # Access control
    allow 127.0.0.1;
    allow ::1;
    allow 192.168.0.0/16;
    allow 10.0.0.0/8;
    deny all;
    
    # Nginx status
    location /nginx_status {
        stub_status on;
        access_log off;
    }
    
    # Health check
    location /health {
        access_log off;
        default_type text/plain;
        return 200 "Monitoring Health: OK\nLoad Balancer IP: $DEFAULT_LB_IP\nTimestamp: \$time_local\nServer: \$hostname\nNginx Version: \$nginx_version\n";
    }
    
    # JSON health check
    location /health/json {
        access_log off;
        default_type application/json;
        return 200 '{"status":"healthy","lb_ip":"$DEFAULT_LB_IP","timestamp":"\$time_iso8601","server":"\$hostname","nginx_version":"\$nginx_version","connections":{"active":"\$connections_active","reading":"\$connections_reading","writing":"\$connections_writing","waiting":"\$connections_waiting"}}';
    }
    
    # Configuration info
    location /info {
        access_log off;
        default_type text/plain;
        return 200 "Load Balancer Information\n========================\nIP: $DEFAULT_LB_IP\nSSL: $USE_SSL\nSSL Type: $SSL_TYPE\nGenerated: $(date)\nUpstream Servers: See /etc/nginx/conf.d/upstream.conf\n";
    }
}
EOF
}

# Setup log rotation
setup_log_rotation() {
    log "Setting up log rotation..."
    
    sudo tee /etc/logrotate.d/nginx-loadbalancer > /dev/null << 'EOF'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    sharedscripts
    prerotate
        if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
            run-parts /etc/logrotate.d/httpd-prerotate; \
        fi
    endscript
    postrotate
        invoke-rc.d nginx rotate >/dev/null 2>&1
    endscript
}
EOF
    
    log "Log rotation configured successfully"
}

# Performance testing function
run_performance_test() {
    local test_enabled=${RUN_PERFORMANCE_TEST:-false}
    
    if [[ "$test_enabled" != "true" ]]; then
        log "Performance testing disabled"
        return 0
    fi
    
    log "Running basic performance test..."
    
    # Check if ab (Apache Bench) is available
    if ! command -v ab >/dev/null 2>&1; then
        warning "Apache Bench (ab) not available, skipping performance test"
        info "Install with: sudo apt install apache2-utils"
        return 0
    fi
    
    local protocol="http"
    if [[ "$USE_SSL" == "true" ]]; then
        protocol="https"
    fi
    
    local test_url="${protocol}://$DEFAULT_LB_IP/health"
    
    log "Testing URL: $test_url"
    log "Running 100 requests with 5 concurrent connections..."
    
    if ab -n 100 -c 5 -q "$test_url" > /tmp/ab_test.log 2>&1; then
        local rps=$(grep "Requests per second" /tmp/ab_test.log | awk '{print $4}')
        local avg_time=$(grep "Time per request" /tmp/ab_test.log | head -1 | awk '{print $4}')
        
        log "Performance test completed successfully"
        info "Requests per second: $rps"
        info "Average response time: ${avg_time}ms"
    else
        warning "Performance test failed - this is normal during initial setup"
        info "You can run manual tests after the service is fully started"
    fi
    
    rm -f /tmp/ab_test.log
}

# Create management scripts
create_management_scripts() {
    log "Creating management scripts..."
    
    # Create main management script
    cat > /tmp/nginx-lb-manage << 'MANAGEMENT_SCRIPT'
#!/bin/bash
# Nginx Load Balancer Management Script

CONFIG_FILE="/etc/nginx-lb/config.env"
SCRIPT_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

show_status() {
    echo "=== Nginx Load Balancer Status ==="
    systemctl status nginx --no-pager -l
    echo
    echo "=== Configuration ==="
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        echo "Load Balancer IP: $DEFAULT_LB_IP"
        echo "SSL Enabled: $USE_SSL"
        echo "SSL Type: $SSL_TYPE"
    else
        error "Configuration file not found: $CONFIG_FILE"
    fi
    echo
    echo "=== Active Connections ==="
    curl -s http://127.0.0.1:8080/nginx_status 2>/dev/null || echo "Monitoring not available"
}

show_logs() {
    local log_type=${1:-access}
    case $log_type in
        "access")
            tail -f /var/log/nginx/access.log
            ;;
        "error")
            tail -f /var/log/nginx/error.log
            ;;
        "lb")
            tail -f /var/log/nginx/lb_access.log
            ;;
        *)
            echo "Usage: $0 logs [access|error|lb]"
            ;;
    esac
}

test_config() {
    log "Testing Nginx configuration..."
    if nginx -t; then
        log "Configuration test passed"
        return 0
    else
        error "Configuration test failed"
        return 1
    fi
}

reload_config() {
    if test_config; then
        log "Reloading Nginx configuration..."
        systemctl reload nginx
        log "Configuration reloaded successfully"
    else
        error "Cannot reload - configuration has errors"
        return 1
    fi
}

show_health() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        local protocol="http"
        if [[ "$USE_SSL" == "true" ]]; then
            protocol="https"
        fi
        
        echo "=== Load Balancer Health Check ==="
        curl -s "${protocol}://$DEFAULT_LB_IP/health" || echo "Health check failed"
        echo
        echo
        echo "=== Detailed Health Check ==="
        curl -s "${protocol}://$DEFAULT_LB_IP/health/detailed" | python3 -m json.tool 2>/dev/null || echo "Detailed health check failed"
    else
        error "Configuration file not found"
    fi
}

show_upstream_status() {
    echo "=== Upstream Server Configuration ==="
    grep -A 20 "upstream.*servers" /etc/nginx/conf.d/upstream.conf 2>/dev/null || echo "Upstream configuration not found"
}

case $1 in
    "status")
        show_status
        ;;
    "logs")
        show_logs $2
        ;;
    "test")
        test_config
        ;;
    "reload")
        reload_config
        ;;
    "health")
        show_health
        ;;
    "upstream")
        show_upstream_status
        ;;
    "restart")
        log "Restarting Nginx service..."
        systemctl restart nginx
        log "Service restarted"
        ;;
    *)
        echo "Nginx Load Balancer Management"
        echo "Usage: $0 [status|logs|test|reload|health|upstream|restart]"
        echo
        echo "Commands:"
        echo "  status    - Show service status and configuration"
        echo "  logs      - Show logs [access|error|lb]"
        echo "  test      - Test Nginx configuration"
        echo "  reload    - Reload configuration"
        echo "  health    - Check load balancer health"
        echo "  upstream  - Show upstream server status"
        echo "  restart   - Restart Nginx service"
        ;;
esac
MANAGEMENT_SCRIPT
    
    sudo cp /tmp/nginx-lb-manage /usr/local/bin/nginx-lb-manage
    rm /tmp/nginx-lb-manage
    
    sudo chmod +x /usr/local/bin/nginx-lb-manage
    
    # Create backup script
    cat > /tmp/nginx-lb-backup << 'BACKUP_SCRIPT'
#!/bin/bash
# Nginx Load Balancer Backup Script

BACKUP_BASE_DIR="/var/backups/nginx-lb"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_BASE_DIR/$TIMESTAMP"

log() { echo -e "\033[0;32m[INFO]\033[0m $1"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $1" >&2; }

# Create backup directory
sudo mkdir -p "$BACKUP_DIR"

# Backup configuration files
log "Backing up configuration files..."
sudo cp -r /etc/nginx "$BACKUP_DIR/"
sudo cp -r /etc/nginx-lb "$BACKUP_DIR/" 2>/dev/null || true

# Backup SSL certificates
if [[ -d /etc/nginx/ssl ]]; then
    log "Backing up SSL certificates..."
    sudo cp -r /etc/nginx/ssl "$BACKUP_DIR/ssl"
fi

# Create info file
cat > /tmp/backup_info.txt << BACKUP_INFO
Backup created: $(date)
Hostname: $(hostname)
Nginx version: $(nginx -v 2>&1)
System: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")
BACKUP_INFO

sudo cp /tmp/backup_info.txt "$BACKUP_DIR/"
rm /tmp/backup_info.txt

log "Backup created: $BACKUP_DIR"

# Clean old backups (keep last 10)
log "Cleaning old backups..."
cd "$BACKUP_BASE_DIR"
sudo ls -t | tail -n +11 | sudo xargs rm -rf 2>/dev/null || true

log "Backup completed successfully"
BACKUP_SCRIPT
    
    sudo cp /tmp/nginx-lb-backup /usr/local/bin/nginx-lb-backup
    rm /tmp/nginx-lb-backup
    
    sudo chmod +x /usr/local/bin/nginx-lb-backup
    
    log "Management scripts created successfully"
    info "Use 'nginx-lb-manage status' to check load balancer status"
    info "Use 'nginx-lb-backup' to create configuration backups"
}

# Main installation function
main() {
    log "Starting Enhanced Nginx Load Balancer Setup..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "🔧 IP-Only Optimized Load Balancer Setup"
    info "🔒 Minimal SSL Configuration"
    info "🎯 Production-Ready with Enhanced Management"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    
    # Step 1: Prerequisites
    log "Step 1: Checking prerequisites..."
    check_prerequisites
    
    # Step 2: Load configuration
    log "Step 2: Loading configuration..."
    load_configuration
    
    # Step 3: Validate servers (optional connectivity check)
    log "Step 3: Validating server connectivity..."
    validate_servers
    
    # Step 4: System Update
    log "Step 4: Updating system packages..."
    sudo apt update && sudo apt upgrade -y
    if [[ $? -ne 0 ]]; then
        error "System update failed"
        exit 1
    fi
    
    # Step 5: Install packages
    log "Step 5: Installing Nginx and dependencies..."
    sudo apt install -y nginx nginx-extras openssl curl net-tools apache2-utils
    if [[ $? -ne 0 ]]; then
        error "Package installation failed"
        exit 1
    fi
    
    # Step 6: Create backup
    log "Step 6: Creating backup of original configuration..."
    BACKUP_DIR="/etc/nginx.backup.$(date +%Y%m%d_%H%M%S)"
    sudo cp -r /etc/nginx "$BACKUP_DIR"
    log "Original configuration backed up to: $BACKUP_DIR"
    
    # Step 7: Create directories
    log "Step 7: Creating required directories..."
    sudo mkdir -p /etc/nginx/ssl
    sudo mkdir -p /var/cache/nginx
    sudo mkdir -p /var/log/nginx
    sudo mkdir -p /etc/nginx/conf.d
    sudo mkdir -p /etc/nginx/sites-available
    sudo mkdir -p /etc/nginx/sites-enabled
    sudo mkdir -p /etc/nginx/snippets
    
    # Set permissions
    sudo chown -R www-data:www-data /var/cache/nginx
    sudo chown -R www-data:www-data /var/log/nginx
    sudo chmod -R 755 /var/cache/nginx
    sudo chmod -R 755 /var/log/nginx
    
    # Step 8: SSL Configuration
    log "Step 8: Setting up SSL configuration..."
    setup_ssl_configuration
    
    # Step 9: Generate configurations
    log "Step 9: Generating Nginx configurations..."
    create_nginx_main_config
    generate_upstream_config
    create_loadbalancer_config
    create_monitoring_config
    
    # Step 10: Setup log rotation
    log "Step 10: Setting up log rotation..."
    setup_log_rotation
    
    # Step 11: Activate configuration
    log "Step 11: Activating load balancer configuration..."
    sudo ln -sf /etc/nginx/sites-available/loadbalancer /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default
    
    # Step 12: Test configuration
    log "Step 12: Testing Nginx configuration..."
    if sudo nginx -t; then
        log "✓ Nginx configuration test passed"
    else
        error "✗ Nginx configuration test failed"
        error "Please check the configuration files for errors"
        exit 1
    fi
    
    # Step 13: Start services
    log "Step 13: Starting and enabling Nginx service..."
    sudo systemctl restart nginx
    sudo systemctl enable nginx
    
    # Wait for service to start
    sleep 3
    
    # Step 14: Verify service
    log "Step 14: Verifying Nginx service status..."
    if sudo systemctl is-active --quiet nginx; then
        log "✓ Nginx service is running successfully"
    else
        error "✗ Nginx service failed to start"
        sudo systemctl status nginx --no-pager
        exit 1
    fi
    
    # Step 15: Configure firewall
    log "Step 15: Configuring firewall..."
    if command -v ufw >/dev/null 2>&1; then
        sudo ufw allow 'Nginx Full' 2>/dev/null || true
        sudo ufw allow 22/tcp 2>/dev/null || true
        if [[ "$USE_SSL" == "true" ]]; then
            sudo ufw allow 443/tcp 2>/dev/null || true
        fi
        info "✓ Firewall rules configured"
    else
        warning "UFW not found - configure firewall manually if needed"
    fi
    
    # Step 16: Create management scripts
    log "Step 16: Creating management scripts..."
    create_management_scripts
    
    # Step 17: Performance test (optional)
    log "Step 17: Running performance test..."
    run_performance_test
    
    # Step 18: Final verification
    log "Step 18: Final verification..."
    local protocol="http"
    if [[ "$USE_SSL" == "true" ]]; then
        protocol="https"
    fi
    
    local health_url="${protocol}://$DEFAULT_LB_IP/health"
    
    log "Testing health endpoint: $health_url"
    if curl -s -k "$health_url" >/dev/null 2>&1; then
        log "✓ Health check endpoint is working"
    else
        warning "✗ Health check endpoint may not be working"
        warning "This could be normal if upstream servers are not ready"
    fi
    
    # Setup complete
    display_final_summary
}

# Display final summary
display_final_summary() {
    echo
    log "🎉 Nginx Load Balancer Setup Completed Successfully!"
    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "📋 SETUP SUMMARY"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    source "$CONFIG_FILE"
    
    info "🌐 Load Balancer Information:"
    info "   • IP Address: $DEFAULT_LB_IP"
    info "   • SSL Enabled: $USE_SSL"
    if [[ "$USE_SSL" == "true" ]]; then
        info "   • SSL Type: $SSL_TYPE"
    fi
    info "   • Configuration: $CONFIG_FILE"
    info "   • Backup Created: $BACKUP_DIR"
    
    echo
    info "🔗 Access URLs:"
    info "   • HTTP: http://$DEFAULT_LB_IP"
    if [[ "$USE_SSL" == "true" ]]; then
        info "   • HTTPS: https://$DEFAULT_LB_IP"
        if [[ "$SSL_TYPE" == "self-signed" ]]; then
            warning "   ⚠️  Browser will show security warnings for self-signed certificate"
        fi
    fi
    info "   • Health Check: http://$DEFAULT_LB_IP/health"
    info "   • Monitoring: http://127.0.0.1:${METRICS_PORT:-8080}/nginx_status"
    
    echo
    info "🔧 Management Commands:"
    info "   • Check Status: nginx-lb-manage status"
    info "   • View Logs: nginx-lb-manage logs [access|error|lb]"
    info "   • Test Config: nginx-lb-manage test"
    info "   • Reload Config: nginx-lb-manage reload"
    info "   • Health Check: nginx-lb-manage health"
    info "   • Create Backup: nginx-lb-backup"
    
    echo
    info "📁 Important Files:"
    info "   • Main Config: /etc/nginx/nginx.conf"
    info "   • Site Config: /etc/nginx/sites-available/loadbalancer"
    info "   • Upstream Config: /etc/nginx/conf.d/upstream.conf"
    info "   • SSL Certificates: /etc/nginx/ssl/"
    info "   • Load Balancer Config: $CONFIG_FILE"
    
    echo
    info "📊 Server Pools Configured:"
    info "   • Kubernetes Servers: ${#KUBERNETES_IPS[@]} servers"
    info "   • Storage Servers: ${#STORAGE_IPS[@]} servers"
    info "   • Beta API Servers: ${#BETAKUBERNETES_IPS[@]} servers"
    info "   • WebSocket Servers: ${#WEBSOCKET_IPS[@]} servers"
    
    echo
    if [[ "$USE_SSL" == "true" && "$SSL_TYPE" == "self-signed" ]]; then
        warning "⚠️  SSL IMPORTANT NOTES:"
        warning "   • Self-signed certificate will show browser warnings"
        warning "   • For production, consider using:"
        warning "     - Proper domain with Let's Encrypt certificate"
        warning "     - Internal CA certificate"
        warning "     - HTTP-only for internal networks"
        echo
    fi
    
    info "🔄 Next Steps:"
    info "   1. Verify upstream servers are running and accessible"
    info "   2. Test load balancer functionality with real traffic"
    info "   3. Set up monitoring and alerting"
    info "   4. Configure log analysis tools"
    info "   5. Plan for certificate renewal (if using SSL)"
    
    echo
    info "📞 Troubleshooting:"
    info "   • Check service: systemctl status nginx"
    info "   • Test config: nginx -t"
    info "   • View errors: journalctl -u nginx -f"
    info "   • Check connectivity: nginx-lb-manage upstream"
    
    echo
    log "✅ Load balancer is ready for production use!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi