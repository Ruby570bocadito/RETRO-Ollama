import json
import requests
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

BASE_DIR = Path(__file__).parent.parent.parent
CVE_DIR = BASE_DIR / "cve_data"
CVE_DIR.mkdir(exist_ok=True)
CVE_DB_FILE = CVE_DIR / "cisa_kev.json"
CVE_DB_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def download_cisa_kev(force: bool = False) -> bool:
    if CVE_DB_FILE.exists() and not force:
        age = datetime.now().timestamp() - CVE_DB_FILE.stat().st_mtime
        if age < 86400:
            return True
    
    try:
        print("Descargando CISA KEV database...")
        r = requests.get(CVE_DB_URL, timeout=60)
        if r.status_code == 200:
            data = r.json()
            with open(CVE_DB_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"✓ Descargados {len(data.get('vulnerabilities', []))} CVEs")
            return True
    except Exception as e:
        print(f"Error descargando: {e}")
    return False

def load_cve_db() -> List[Dict]:
    if CVE_DB_FILE.exists():
        try:
            with open(CVE_DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("vulnerabilities", [])
        except:
            pass
    return []

def search_cve(cve_id: str) -> Optional[Dict]:
    cves = load_cve_db()
    cve_id = cve_id.upper()
    for cve in cves:
        if cve.get("cveID", "").upper() == cve_id:
            return cve
    return None

def search_by_keyword(keyword: str) -> List[Dict]:
    cves = load_cve_db()
    keyword = keyword.lower()
    results = []
    
    for cve in cves:
        vendor = cve.get("vendorProject", "").lower()
        product = cve.get("product", "").lower()
        desc = cve.get("shortDescription", "").lower()
        
        if keyword in vendor or keyword in product or keyword in desc:
            results.append(cve)
    
    return results[:50]

def search_by_vendor(vendor: str) -> List[Dict]:
    cves = load_cve_db()
    vendor = vendor.lower()
    results = []
    
    for cve in cves:
        if vendor in cve.get("vendorProject", "").lower():
            results.append(cve)
    
    return results[:50]

def get_recent_exploits(days: int = 30) -> List[Dict]:
    cves = load_cve_db()
    results = []
    cutoff = datetime.now().timestamp() - (days * 86400)
    
    for cve in cves:
        date_str = cve.get("dateAdded", "")
        try:
            date = datetime.strptime(date_str, "%Y-%m-%d").timestamp()
            if date >= cutoff:
                results.append(cve)
        except:
            pass
    
    return sorted(results, key=lambda x: x.get("dateAdded", ""), reverse=True)[:20]

def get_stats() -> Dict:
    cves = load_cve_db()
    if not cves:
        return {"total": 0}
    
    vendors = {}
    for cve in cves:
        vendor = cve.get("vendorProject", "Unknown")
        vendors[vendor] = vendors.get(vendor, 0) + 1
    
    top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return {
        "total": len(cves),
        "last_update": CVE_DB_FILE.stat().st_mtime if CVE_DB_FILE.exists() else 0,
        "top_vendors": top_vendors
    }

def format_cve(cve: Dict) -> str:
    lines = [
        f"CVE: {cve.get('cveID', 'N/A')}",
        f"Vendor: {cve.get('vendorProject', 'N/A')}",
        f"Product: {cve.get('product', 'N/A')}",
        f"Date Added: {cve.get('dateAdded', 'N/A')}",
        f"Due Date: {cve.get('dueDate', 'N/A')}",
        f"Severity: {cve.get('knownRansomwareCampaignUse', 'N/A')}",
        "",
        f"Description: {cve.get('shortDescription', 'N/A')}"
    ]
    return "\n".join(lines)
