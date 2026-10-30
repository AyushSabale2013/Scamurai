"""Known-good regression test list.

All URLs are genuine, publicly accessible legitimate websites with deep paths,
queries, UUIDs, app routes, international sites, Indian banking/gov sites, etc.
MUST NEVER be classified as likely_phishing.
"""

import csv
from pathlib import Path

DEST = Path(__file__).resolve().parent / "known_good_urls.csv"

URLS = [
    # Primary reported bug URLs
    "https://claude.ai/chat/305c187a-fc1f-4d9a-9063-3f0b53b47a2a",
    "https://chatgpt.com/c/6ae3364a-1440-83e8-be31-1e5aefa525c5",
    "https://gemini.google.com/app/abc123def456",
    "https://chat.openai.com/chat",
    "https://bard.google.com/chat",

    # Developer & Tech Documentation
    "https://github.com/anthropics/anthropic-sdk-python",
    "https://github.com/openai/openai-python/blob/main/README.md",
    "https://github.com/pallets/flask/issues/5234",
    "https://github.com/microsoft/vscode/pull/12345",
    "https://gitlab.com/gitlab-org/gitlab/-/issues/43210",
    "https://bitbucket.org/atlassian/python-bitbucket/src/master/",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://docs.python.org/3/tutorial/classes.html#generators",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise",
    "https://reactjs.org/docs/getting-started.html",
    "https://vuejs.org/guide/essentials/template-syntax.html",
    "https://angular.io/guide/architecture-components",
    "https://nextjs.org/docs/app/building-your-application/routing",
    "https://fastapi.tiangolo.com/tutorial/first-steps/",
    "https://pypi.org/project/scikit-learn/",
    "https://npmjs.com/package/react",
    "https://huggingface.co/models",
    "https://www.kaggle.com/datasets",
    "https://stackoverflow.com/questions/12345678/how-to-do-something",
    "https://stackoverflow.com/questions/tagged/python",
    "https://serverfault.com/questions/123456/server-config",
    "https://superuser.com/questions/654321/windows-issue",
    "https://askubuntu.com/questions/1234567/ubuntu-question",

    # Search engines with queries
    "https://www.google.com/search?q=weather+today",
    "https://www.google.com/search?q=python+urllib+parse&hl=en",
    "https://www.bing.com/search?q=machine+learning+tutorial",
    "https://duckduckgo.com/?q=phishing+detection&t=h_",
    "https://search.yahoo.com/search?p=cybersecurity+news",

    # News and Media
    "https://www.bbc.com/news/technology-12345678",
    "https://www.bbc.com/news/world-asia-india-67890123",
    "https://www.nytimes.com/2024/01/15/technology/ai-safety.html",
    "https://www.theguardian.com/technology/2024/jan/15/ai-regulation",
    "https://www.reuters.com/technology/ai-regulation-2024-01-15/",
    "https://edition.cnn.com/2024/01/15/tech/ai-safety/index.html",
    "https://timesofindia.indiatimes.com/india/latest-news/articleshow/12345678.cms",
    "https://www.ndtv.com/india-news/article-headline-4567890",
    "https://www.hindustantimes.com/india-news/story-slug-101234567890123.html",

    # Social and Collaboration
    "https://twitter.com/OpenAI/status/1234567890123456789",
    "https://www.reddit.com/r/MachineLearning/comments/abc123/new_paper/",
    "https://www.linkedin.com/in/john-doe-12345678/",
    "https://www.linkedin.com/company/microsoft/posts/",
    "https://www.instagram.com/p/CxYzAbCdEf/",
    "https://www.facebook.com/groups/123456789/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/playlist?list=PLRqwX-V7Uu6ZiZxtDDRCi6uhfTH4FilpH",

    # Productivity, Cloud and SaaS
    "https://mail.google.com/mail/u/0/#inbox",
    "https://mail.google.com/mail/u/0/#sent",
    "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms/edit",
    "https://docs.google.com/spreadsheets/d/1abc2def3ghi4jkl5mno6pqr7stu8vwx9yz/edit#gid=0",
    "https://docs.google.com/forms/d/e/1FAIpQLSdabc123/viewform",
    "https://drive.google.com/file/d/1abc2def3ghi4jkl/view",
    "https://calendar.google.com/calendar/u/0/r/month",
    "https://meet.google.com/abc-defg-hij",
    "https://zoom.us/j/12345678901?pwd=abcdefghijklmnop",
    "https://teams.microsoft.com/l/meetup-join/19%3ameeting_abc123/0",
    "https://notion.so/workspace/Getting-Started-abc123def456",
    "https://trello.com/b/abc123/project-board",
    "https://slack.com/app",
    "https://app.slack.com/client/T12345/C67890",
    "https://outlook.live.com/mail/0/inbox",
    "https://console.aws.amazon.com/ec2/home?region=us-east-1#Instances:",
    "https://portal.azure.com/#blade/HubsExtension/BrowseAll",
    "https://console.cloud.google.com/compute/instances?project=my-project",
    "https://vercel.com/dashboard",
    "https://app.netlify.com/sites/my-site/overview",
    "https://dashboard.heroku.com/apps/my-app",

    # Indian Government and Banking
    "https://irctc.co.in/nget/train-search",
    "https://irctc.co.in/nget/booking/pnr-enquiry",
    "https://erail.in/train-enquiry",
    "https://onlinesbi.sbi/sbijava/retail/login.htm",
    "https://retail.onlinesbi.sbi/retail/login.htm",
    "https://www.onlinesbi.sbi/sbijava/sbiconnect/hdfcbank",
    "https://netbanking.hdfcbank.com/netbanking/",
    "https://www.icicibank.com/personal-banking/accounts/savings-account",
    "https://www.axisbank.com/retail/accounts/savings-account",
    "https://www.kotak.com/en/personal-banking/accounts/savings-account.html",
    "https://www.incometax.gov.in/iec/foportal/",
    "https://incometaxindiaefiling.gov.in/home",
    "https://www.digilocker.gov.in/",
    "https://digilocker.meripehchaan.gov.in/public/signin",
    "https://www.npci.org.in/what-we-do/upi/product-overview",
    "https://paytm.com/recharge",
    "https://paytm.com/electricity-bill-payment",
    "https://www.phonepe.com/business/",
    "https://www.bharatpe.com/merchant",
    "https://epost.gov.in/epost/pages/trackConsignment.jsp",
    "https://www.indiapost.gov.in/VAS/Pages/trackconsignment.aspx",
    "https://eprocure.gov.in/eprocure/app",
    "https://gem.gov.in/",
    "https://aadhaar.uidai.gov.in/verify-aadhaar",
    "https://myaadhaar.uidai.gov.in/",
    "https://www.passportindia.gov.in/AppOnlineProject/user/userLogin",
    "https://www.jiomart.com/",
    "https://www.jio.com/selfcare/plans/mobility/prepaid-plans",
    "https://www.airtel.in/recharge-online",
    "https://www.vodafone.in/explore/recharge/recharge-plans",
    "https://vahan.parivahan.gov.in/vahan4dashboard/",

    # Global Banking and Finance
    "https://www.paypal.com/myaccount/summary",
    "https://www.paypal.com/invoice/create",
    "https://pay.google.com/gp/w/home/activity",
    "https://www.apple.com/apple-pay/",
    "https://stripe.com/docs/payments/payment-intents",
    "https://dashboard.stripe.com/test/payments",
    "https://www.bankofamerica.com/deposits/checking-accounts/",
    "https://www.chase.com/personal/checking",
    "https://www.wellsfargo.com/checking/",

    # Authentication / Login on Legitimate Domains
    "https://accounts.google.com/signin/v2/identifier",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "https://login.yahoo.com/",
    "https://id.apple.com/account",
    "https://account.live.com/password/reset",
    "https://www.netflix.com/login",
    "https://www.spotify.com/account/overview/",
    "https://secure.indeed.com/auth",
    "https://auth0.com/docs/authenticate",
    "https://signin.aws.amazon.com/console",

    # E-commerce and Retail
    "https://www.amazon.com/dp/B0BSHF7WHW",
    "https://www.amazon.in/dp/B0BSHF7WHW?ref=cm_sw_r_cp_ud_dp_abc123",
    "https://www.flipkart.com/samsung-galaxy-s24/p/itm123456789",
    "https://www.ebay.com/itm/123456789012",
    "https://www.etsy.com/listing/1234567890/handmade-item",
    "https://www.myntra.com/tshirts/brand/product-name/12345678/buy",
    "https://www.walmart.com/ip/Product-Name/12345678",
    "https://www.target.com/p/item-name/-/A-12345678",

    # Reference and Encyclopedias
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Machine_learning#Approaches",
    "https://en.wiktionary.org/wiki/phishing",
    "https://www.britannica.com/technology/artificial-intelligence",
    "https://archive.org/details/texts",
    "https://web.archive.org/web/2024/https://example.com",

    # URL Shorteners
    "https://bit.ly/3abc123",
    "https://t.co/abc123XYZ",
    "https://goo.gl/maps/abc123",

    # Standard Homepages (no path)
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.com",
    "https://www.github.com",
    "https://www.reddit.com",
    "https://www.linkedin.com",
    "https://www.youtube.com",
    "https://example.com",

    # International and Government Sites
    "https://www.government.nl/topics/cybersecurity",
    "https://www.gouvernement.fr/les-actions-du-gouvernement",
    "https://www.canada.ca/en/services/benefits.html",
    "https://www.gov.uk/government/organisations",
    "https://www.australia.gov.au/information-and-services",
    "https://münchen.de/rathaus",
    "https://日本語.jp/テスト",

    # Developer Blogs & Platforms
    "https://news.ycombinator.com/item?id=12345678",
    "https://lobste.rs/newest",
    "https://medium.com/@user/article-title-abc123def456",
    "https://dev.to/username/article-title-1a2b",
    "https://codepen.io/user/pen/abc123",
    "https://codesandbox.io/s/react-example-abc123",
    "https://httpbin.org/get",
    "https://jsonplaceholder.typicode.com/posts/1",
    "https://api.github.com/repos/octocat/Hello-World",
    "https://fonts.google.com/specimen/Roboto",
    "https://translate.google.com/?sl=en&tl=hi&text=hello",
    "https://maps.google.com/maps?q=Mumbai",
]

def main():
    DEST.parent.mkdir(parents=True, exist_ok=True)
    with open(DEST, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "category", "label"])
        for u in URLS:
            w.writerow([u, "legitimate_known_good", 1])
    print(f"Wrote {len(URLS)} known-good URLs to {DEST}")

if __name__ == "__main__":
    main()
