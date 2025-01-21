import requests
from bs4 import BeautifulSoup

# List of platforms and their parsing rules for profile details
platforms = [
    {
        "url": "https://www.twitter.com/{}",
        "exists_text": "joined Twitter",
        "follower_tag": {"name": "span", "attrs": {"class": "followers"}},
        "location_tag": {"name": "span", "attrs": {"class": "ProfileHeaderCard-locationText"}},
        "email_tag": None,
    },
    {
        "url": "https://www.instagram.com/{}",
        "exists_text": "This account is private",
        "follower_tag": {"name": "meta", "attrs": {"name": "description"}},
        "location_tag": None,
        "email_tag": None,
    },
    {
        "url": "https://www.github.com/{}",
        "exists_text": "followers",
        "follower_tag": {"name": "span", "attrs": {"class": "Counter"}},
        "location_tag": {"name": "span", "attrs": {"class": "p-label"}},
        "email_tag": {"name": "a", "attrs": {"href": lambda x: x and x.startswith("mailto:")}},
    },
    {
        "url": "https://www.facebook.com/{}",
        "exists_text": "Facebook",
        "follower_tag": None,
        "location_tag": None,
        "email_tag": None,
    },
    {
        "url": "https://www.pinterest.com/{}",
        "exists_text": "Pinterest",
        "follower_tag": {"name": "span", "attrs": {"class": "followers"}},
        "location_tag": None,
        "email_tag": None,
    },
    {
        "url": "https://www.reddit.com/user/{}",
        "exists_text": "u/",
        "follower_tag": {"name": "span", "attrs": {"class": "followers"}},
        "location_tag": None,
        "email_tag": None,
    },
    {
        "url": "https://www.tumblr.com/blog/{}",
        "exists_text": "Tumblr",
        "follower_tag": {"name": "span", "attrs": {"class": "follower-count"}},
        "location_tag": None,
        "email_tag": None,
    },
    {
        "url": "https://www.tiktok.com/@{}",
        "exists_text": "TikTok",
        "follower_tag": {"name": "strong", "attrs": {"class": "follower-count"}},
        "location_tag": None,
        "email_tag": None,
    },
    {
        "url": "https://www.youtube.com/c/{}",
        "exists_text": "YouTube",
        "follower_tag": {"name": "yt-formatted-string", "attrs": {"class": "style-scope ytd-c4-tabbed-header-renderer"}},
        "location_tag": None,
        "email_tag": None,
    },
    {
        "url": "https://www.snapchat.com/add/{}",
        "exists_text": "Snapchat",
        "follower_tag": None,
        "location_tag": None,
        "email_tag": None,
    },
    {
        "url": "https://www.linkedin.com/in/{}",
        "exists_text": "LinkedIn",
        "follower_tag": None,
        "location_tag": {"name": "span", "attrs": {"class": "top-card__location"}},
        "email_tag": None,
    },
]

def ensure_scheme(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url

def scrape_detail(soup, tag):
    if tag is None:
        return None
    
    element = soup.find(tag["name"], tag.get("attrs", {}))
    
    if tag.get("name") == "meta" and "description" in tag["attrs"].get("name", ""):
        if element:
            content = element.get("content", "").split("-")[0]
            return content.strip()
    
    if element:
        if "content" in element.attrs:
            return element["content"]
        elif element.text.strip():
            return element.text.strip()
    return None

def check_profile(username):
    found_profiles = []

    for platform in platforms:
        url = platform["url"].format(username)
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                if platform["exists_text"] in soup.text:
                    print(f"\033[1;32m[+] Profile found: {url}\033[0m")
                    profile_data = {"url": url}
                    profile_data["followers"] = scrape_detail(soup, platform.get("follower_tag"))
                    profile_data["location"] = scrape_detail(soup, platform.get("location_tag"))
                    profile_data["email"] = scrape_detail(soup, platform.get("email_tag"))
                    found_profiles.append(profile_data)
                else:
                    print(f"\033[1;31m[-] No profile found at: {url}\033[0m")
            else:
                print(f"\033[1;31m[-] No profile found at: {url}\033[0m")
        except Exception as e:
            print(f"\033[1;33m[!] Error checking {url}: {e}\033[0m")
    
    return found_profiles

def check_open_redirect(target_url):
    test_urls = [
        # Removed malicious URLs to avoid any real redirect checks
    ]
    for test_url in test_urls:
        redirect_url = f"{target_url}{test_url}"
        try:
            response = requests.get(redirect_url, allow_redirects=True, timeout=3)
            if response.history:
                print(f"\033[1;33m[!] Open redirect found: {redirect_url} redirected to {response.url}\033[0m")
            else:
                print(f"\033[1;32m[*] No open redirect found for {redirect_url}\033[0m")
        except requests.exceptions.RequestException as e:
            print(f"\033[1;33m[!] Error checking open redirect: {e}\033[0m")

def check_outdated_software(target_url):
    try:
        response = requests.get(target_url, timeout=3)
        if "X-Powered-By" in response.headers:
            print(f"\033[1;31m[!] Outdated software found: {response.headers['X-Powered-By']}\033[0m")
        elif "Server" in response.headers:
            print(f"\033[1;32m[*] Server software: {response.headers['Server']}\033[0m")
        else:
            print("\033[1;32m[*] No outdated software detected in headers.\033[0m")
    except requests.exceptions.RequestException as e:
        print(f"\033[1;33m[!] Error checking for outdated software: {e}\033[0m")

def check_sql_injection(target_url, param):
    test_payloads = ["' OR 1=1 --", "' UNION SELECT NULL --", "'; DROP TABLE users --"]
    for payload in test_payloads:
        test_url = f"{target_url}?{param}={payload}"
        try:
            response = requests.get(test_url, timeout=3)
            if "error" in response.text.lower():  
                print(f"\033[1;31m[!] Possible SQL injection vulnerability detected at {test_url}\033[0m")
            else:
                print(f"\033[1;32m[*] No SQL injection vulnerability at {test_url}\033[0m")
        except requests.exceptions.RequestException as e:
            print(f"\033[1;33m[!] Error checking SQL injection: {e}\033[0m")

def check_xss(target_url, param):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{target_url}?{param}={payload}"
    try:
        response = requests.get(test_url, timeout=3)
        if payload in response.text:
            print(f"\033[1;31m[!] Possible XSS vulnerability detected at {test_url}\033[0m")
        else:
            print(f"\033[1;32m[*] No XSS vulnerability at {test_url}\033[0m")
    except requests.exceptions.RequestException as e:
        print(f"\033[1;33m[!] Error checking for XSS: {e}\033[0m")

def check_vulnerabilities(target_url):
    target_url = ensure_scheme(target_url)  
    print(f"\033[1;32m[*] Checking vulnerabilities for {target_url}...\033[0m")
    
    print("\033[1;33m[*] Performing open redirect check...\033[0m")
    check_open_redirect(target_url)
    
    print("\033[1;33m[*] Checking for outdated software...\033[0m")
    check_outdated_software(target_url)
    
    print("\033[1;33m[*] Checking for SQL injection vulnerabilities...\033[0m")
    check_sql_injection(target_url, "username")
    
    print("\033[1;33m[*] Checking for Cross-Site Scripting (XSS) vulnerabilities...\033[0m")
    check_xss(target_url, "query")

def main():
    while True:
        print("\033[1;34m=== Educational Cybersecurity Toolkit ===\033[0m")
        print("1. Check Vulnerabilities")
        print("2. Gather Social Media Info")
        print("0. Exit")
        
        choice = input("\033[1;36mEnter the number of the function you want to use: \033[0m")
        
        if choice == '1':
            target_url = input("\033[1;36mEnter the target URL to check for vulnerabilities: \033[0m")
            check_vulnerabilities(target_url)
        elif choice == '2':
            username = input("\033[1;36mEnter the username to search: \033[0m")
            print(f"\033[1;33mSearching for '{username}' on social media platforms...\n\033[0m")
            profiles = check_profile(username)

            if profiles:
                print("\n\033[1;32mFound profiles:\033[0m")
                for profile in profiles:
                    print(f"\033[1;36mURL: {profile['url']}\033[0m")
                    if profile.get("followers"):
                        print(f"\033[1;36mFollowers: {profile['followers']}\033[0m")
                    if profile.get("location"):
                        print(f"\033[1;36mLocation: {profile['location']}\033[0m")
                    if profile.get("email"):
                        print(f"\033[1;36mEmail: {profile['email']}\033[0m")
                    print("-" * 40)
            else:
                print("\n\033[1;31mNo profiles found.\033[0m")
        elif choice == '0':
            print("\033[1;32mExiting program...\033[0m")
            break
        else:
            print("\033[1;31mInvalid choice! Try again.\033[0m\n")

if __name__ == "__main__":
    main()