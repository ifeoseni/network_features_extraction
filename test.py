# pip3 install requests
import requests
from bs4 import BeautifulSoup
import cloudscraper

# ...
# create a cloudscraper instance
scraper = cloudscraper.create_scraper(
    browser={
        "browser": "chrome",
        "platform": "windows",
    },
)

# specify the target URL
url = "http://dannyvanleeuwen.nl/hgf65g"
# ...
# request the target website
response = scraper.get(url)

# get the response status code
print(f"The status code for {url} is {response.status_code}")


