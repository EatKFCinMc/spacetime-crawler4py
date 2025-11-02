
from bs4 import BeautifulSoup

with open("test_text.html", "r") as f:
    raw_html = f.read()
    html = BeautifulSoup(raw_html, 'html.parser')
    urls = [a['href'] for a in html.find_all('a', href=True)]
    text = html.get_text()
    print(text.split())
    print(len(text))
    print(len(raw_html))
    print(len(text) / len(raw_html))