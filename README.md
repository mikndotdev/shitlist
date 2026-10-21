# shitlist

<p align="center">
 <img src="https://cdn.mikn.dev/branding/mikan-vtube.png" width="100">
</p>

List of IPs that scrape restricted paths, such as `.env` and various restricted paths 
(triggers OWASP CRS 930100, 930120, 930130, 930140, 920440, 920500) that have been caught from our own proxy logs serving live traffic.
<br><br>
We also add a "lure domain" to our proxy once a day, to catch scrapers looking at new entries in Certificate Transparency logs.
<br><br>
This repository is automatically updated every hour, and IPs found are in [restricted-ips.txt](restricted-ips.txt). 
A file listing IPs by country and ASN can be found in [analytics.md](analytics.md)

## Retention Policy

- An IP address is automatically removed once it hasn't been seen in 30 days.