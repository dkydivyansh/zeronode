import os
import re
import urllib.request
import urllib.parse
from urllib.error import HTTPError

# Google Fonts URLs (with display=swap appended at the end to make regex easier, but Google uses standard params anyway)
FONT_URLS = [
    "https://fonts.googleapis.com/css2?family=Noto+Serif:wght@400;700&family=Inter:wght@300;400;500&family=Space+Grotesk:wght@300;400;700&display=swap",
    "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"
]

TARGET_CSS_DIR = r"x:\projects\valt\app\static\css"
TARGET_FONTS_DIR = r"x:\projects\valt\app\static\fonts"

os.makedirs(TARGET_CSS_DIR, exist_ok=True)
os.makedirs(TARGET_FONTS_DIR, exist_ok=True)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

fonts_css_content = []

for url in FONT_URLS:
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    try:
        with urllib.request.urlopen(req) as response:
            css = response.read().decode('utf-8')
            
            # Find all woff2 URLs
            urls = re.findall(r"url\((https://[^)]+)\)", css)
            
            for font_url in set(urls):
                font_name = font_url.split('/')[-1]
                local_path = os.path.join(TARGET_FONTS_DIR, font_name)
                
                # Download font binary
                if not os.path.exists(local_path):
                    print(f"Downloading {font_name}...")
                    try:
                        urllib.request.urlretrieve(font_url, local_path)
                    except Exception as e:
                        print(f"Failed to download {font_url}: {e}")
                
                # Replace absolute URL with relative path for Flask
                # URL in browser will be /static/fonts/font_name depending on location, but relative to CSS is ../fonts/font_name
                css = css.replace(font_url, f"../fonts/{font_name}")
            
            fonts_css_content.append(css)
    except HTTPError as e:
        print(f"HTTPError on {url}: {e}")

final_css = "\n".join(fonts_css_content)
with open(os.path.join(TARGET_CSS_DIR, 'fonts.css'), 'w', encoding='utf-8') as f:
    f.write(final_css)

print("Font localization complete.")
