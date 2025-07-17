import requests
import validators
import time

VT_API_KEY = '1e2841b3fc99e9c3e34613de1ee3ffc675a1948039e00f029893f8bbcec6763c'

SUSPICIOUS_KEYWORDS = ['login', 'free', 'gift', 'bonus', 'prize', 'claim', 'offer', 'win', 'verify', 'bank', 'password']

def is_valid_url(url):
    return validators.url(url)

def check_https(url):
    return url.lower().startswith('https')

def check_url_reachability(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def is_suspicious_by_keyword(url):
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS)

def scan_url_with_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    params = {'url': url}
    
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
    if response.status_code != 200:
        return "Error connecting to VirusTotal API"
    
    scan_id = response.json()["data"]["id"]
    time.sleep(5)
    result_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    analysis = requests.get(result_url, headers=headers)
    data = analysis.json()
    stats = data["data"]["attributes"]["stats"]
    if stats["malicious"] > 0 or stats["suspicious"] > 0:
        return "Malicious or Suspicious"
    else:
        return "Safe"

def main():
    url = input("🔗 Enter the URL to check: ").strip()
    
    if not is_valid_url(url):
        print("❌ Invalid URL format.")
        return
    
    print(f"\n🔎 Checking URL: {url}")
    
    if check_https(url):
        print("✅ HTTPS: Secure connection detected (SSL Enabled)")
    else:
        print("❌ HTTPS: Not Secure (No SSL Detected)")
    
    if not check_url_reachability(url):
        print("⚠️ Warning: Site not reachable or offline.")
        return
    
    if is_suspicious_by_keyword(url):
        print("⚠️ Suspicious Keywords: Risky words found in URL.")
    else:
        print("✅ Suspicious Keywords: None detected.")
    
    print("🛡️ VirusTotal scanning...")
    vt_verdict = scan_url_with_virustotal(url)
    print(f"✅ VirusTotal Verdict: {vt_verdict}")

if __name__ == "__main__":
    main()
