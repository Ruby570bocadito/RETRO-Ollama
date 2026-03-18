from typing import Dict, List, Optional

CODE_SAMPLES = {
    "network_info": {
        "python": '''import socket
import os

def get_network_info():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return f"Hostname: {hostname}\\nIP: {local_ip}"

print(get_network_info())''',
        "bash": '''#!/bin/bash
echo "Hostname: $(hostname)"
echo "IP: $(hostname -I | awk '{print $1}')"
echo "Default Gateway: $(ip route | grep default | awk '{print $3}')"''',
        "powershell": '''$hostname = $env:COMPUTERNAME
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}).IPAddress
Write-Host "Hostname: $hostname"
Write-Host "IP: $ip"'''
    },
    
    "port_scanner": {
        "python": '''import socket

def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

target = input("Target: ")
ports = [21, 22, 80, 443, 3306, 8080]
for port in ports:
    if scan_port(target, port):
        print(f"Port {port}: OPEN")''',
        "powershell": '''$target = Read-Host "Target"
$ports = 21, 22, 80, 443, 3306, 8080
foreach($port in $ports) {
    $result = Test-NetConnection -ComputerName $target -Port $port -WarningAction SilentlyContinue
    if($result.TcpTestSucceeded) {
        Write-Host "Port $port : OPEN" -ForegroundColor Green
    }
}'''
    },
    
    "http_requester": {
        "python": '''import requests

def make_request(url):
    try:
        r = requests.get(url, timeout=10)
        return {
            "status": r.status_code,
            "headers": dict(r.headers),
            "content_length": len(r.text)
        }
    except Exception as e:
        return {"error": str(e)}

result = make_request("https://example.com")
print(result)''',
        "bash": '''#!/bin/bash
curl -I -s https://example.com | head -10'''
    },
    
    "dns_lookup": {
        "python": '''import socket

domain = input("Domain: ")
try:
    ip = socket.gethostbyname(domain)
    print(f"{domain} -> {ip}")
except:
    print("DNS lookup failed")''',
        "powershell": '''$domain = Read-Host "Domain"
Resolve-DnsName -Name $domain | Select-Object Name, IPAddress'''
    },
    
    "hash_calculator": {
        "python": '''import hashlib
import os

def calculate_file_hash(filepath, algorithm="sha256"):
    hash_func = getattr(hashlib, algorithm)()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

filepath = input("File path: ")
if os.path.exists(filepath):
    print(f"MD5: {calculate_file_hash(filepath, 'md5')}")
    print(f"SHA256: {calculate_file_hash(filepath, 'sha256')}")''',
        "powershell": '''$file = Read-Host "File path"
Get-FileHash -Path $file -Algorithm MD5 | Select-Object Hash'''
    },
    
    "subnet_calculator": {
        "python": '''import ipaddress

def subnet_calc(network):
    net = ipaddress.ip_network(network, strict=False)
    print(f"Network: {net.network_address}")
    print(f"Netmask: {net.netmask}")
    print(f"Broadcast: {net.broadcast_address}")
    print(f"Hosts: {net.num_addresses - 2}")

subnet = input("Subnet (e.g., 192.168.1.0/24): ")
subnet_calc(subnet)''',
        "powershell": '''$subnet = "192.168.1.0/24"
$network = [System.Net.IPAddress]::Parse($subnet.Split("/")[0])
$prefix = [int]$subnet.Split("/")[1]
$mask = [System.Net.IPAddress]::Parse(([System.Net.IPAddress]::None).GetAddressBytes() | ForEach-Object { $_ -band [byte]([math]::Pow(2, 8) - 1) -shl ($_ * 8) }[($prefix - 1)..0] | ForEach-Object { [byte]$_ })
Write-Host "Network: $network / $prefix"'''
    },
    
    "banner_grabber": {
        "python": '''import socket

def grab_banner(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
        banner = sock.recv(1024)
        return banner.decode()
    except:
        return "No banner"
    finally:
        sock.close()

target = input("Target IP: ")
port = int(input("Port: "))
print(grab_banner(target, port))''',
        "powershell": '''$target = Read-Host "Target"
$port = [int]Read-Host "Port"
$tcp = New-Object System.Net.Sockets.TcpClient
$tcp.Connect($target, $port)
$stream = $tcp.GetStream()
$buffer = New-Object byte[] 1024
$stream.Read($buffer, 0, 1024)
[System.Text.Encoding]::ASCII.GetString($buffer)'''
    },
    
    "json_formatter": {
        "python": '''import json

data = input("JSON: ")
try:
    parsed = json.loads(data)
    print(json.dumps(parsed, indent=2))
except:
    print("Invalid JSON")''',
        "powershell": '''$json = '{"name": "test", "value": 123}'
$obj = $json | ConvertFrom-Json
$obj | ConvertTo-Json -Depth 10'''
    },
    
    "base64_encoder": {
        "python": '''import base64

text = input("Text to encode: ")
encoded = base64.b64encode(text.encode()).decode()
print(f"Encoded: {encoded}")

decoded = base64.b64decode(encoded.encode()).decode()
print(f"Decoded: {decoded")'''
    },
    
    "timestamp_converter": {
        "python": '''from datetime import datetime

ts = int(input("Timestamp: "))
dt = datetime.fromtimestamp(ts)
print(f"Date: {dt}")
print(f"ISO: {dt.isoformat()}")''',
        "powershell": '''$ts = Read-Host "Timestamp"
[datetime]::FromUnixTimeSeconds($ts)'''
    }
}


def get_code_sample(category: str, language: str = "python") -> Optional[str]:
    """Obtiene ejemplo de código"""
    if category in CODE_SAMPLES:
        if language in CODE_SAMPLES[category]:
            return CODE_SAMPLES[category][language]
    return None


def list_categories() -> List[str]:
    """Lista categorías disponibles"""
    return list(CODE_SAMPLES.keys())


def list_languages() -> List[str]:
    """Lista lenguajes disponibles"""
    languages = set()
    for category in CODE_SAMPLES.values():
        languages.update(category.keys())
    return list(languages)


def search_samples(query: str) -> List[Dict]:
    """Busca ejemplos por categoría"""
    results = []
    for cat in CODE_SAMPLES:
        if query.lower() in cat.lower():
            results.append({
                "category": cat,
                "languages": list(CODE_SAMPLES[cat].keys())
            })
    return results


def get_all_samples() -> Dict:
    """Obtiene todos los ejemplos"""
    return CODE_SAMPLES
