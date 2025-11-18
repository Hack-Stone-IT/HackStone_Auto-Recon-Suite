"""
HackStone Auto Recon Suite - Screenshot Capture Module
Captures screenshots of main domain and subdomains using headless browser.
Developed by HackStone Cybersecurity Company.
"""

import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, WebDriverException

def setup_driver():
    """Set up headless Chrome driver."""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(30)
    return driver

def capture_screenshot(driver, url, output_path):
    """Capture screenshot of a URL and save to output_path."""
    try:
        driver.get(url)
        time.sleep(3)  # Wait for page to load
        driver.save_screenshot(output_path)
        return True
    except (TimeoutException, WebDriverException) as e:
        print(f"Failed to capture screenshot for {url}: {e}")
        return False

def scan(target, subdomains):
    """Capture screenshots for main target and subdomains."""
    screenshots = []

    # Create screenshots directory
    screenshots_dir = f"reports/{target}/screenshots"
    os.makedirs(screenshots_dir, exist_ok=True)

    driver = setup_driver()

    try:
        # Capture main domain screenshot
        main_url = f"https://{target}"
        main_path = f"{screenshots_dir}/{target}_main.png"
        if capture_screenshot(driver, main_url, main_path):
            screenshots.append({
                'url': main_url,
                'path': main_path,
                'type': 'main'
            })

        # Capture subdomain screenshots
        for subdomain in subdomains:
            subdomain_url = f"https://{subdomain.name}"
            subdomain_path = f"{screenshots_dir}/{subdomain.name.replace('.', '_')}.png"
            if capture_screenshot(driver, subdomain_url, subdomain_path):
                screenshots.append({
                    'url': subdomain_url,
                    'path': subdomain_path,
                    'type': 'subdomain'
                })

    finally:
        driver.quit()

    print(f"Captured {len(screenshots)} screenshots")
    return screenshots
