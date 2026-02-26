# Notes on Thoughts and Ideas

## 1. Potential integrations

### 1.1 URLhaus

- `Malpedia API Key` can be added to `abuse.ch` account
to get access to classified `YARA` rules from `Malpedia`

### 1.2 Virustotal

- **Public API constraints and restrictions**
  - The Public API must not be used in commercial products or services.
  - The Public API must not be used in business workflows that do not contribute new files.
  - You are not allowed to register multiple accounts to overcome the aforementioned limitations.

| Action       | Per Minute | Per Day | Per Month |
|--------------|------------|---------|-----------|
| Public Scans | 4          | 500     | 15.500    |


### 1.3 YARA Rules

- `URLhaus` and other sources seem to have `YARA` rules ready for download,
need to download and test if they match our use-case.

### 1.4 Lookyloo

- `Lookyloo` is a tool for web crawling and analysis. But it needs a lot of time to complete the process as it does
- not simply compare the url against a database of known malicious urls.
- Lookyloo also uses vt, urlhaus, etc. but for some reason that data is different from what I get through direct api requests to those services.
- In short, it is unreliable in that aspect.
- But the metadata scrapping cannot be discounted, as such I will use it mainly as a source of metadata and for crosschecking.

### 1.5 Pandora

- Requires a file to be uploaded and does not accept download links.
- Any file would need to be downloaded by us first before it can be uploaded for testing to pandora.

### 1.6 URLScan.io

- Good source of metadata and good indicator of maliciousness.
- Checks with google safe browsing and other indicators.
- Api key required, but with good rates:

| Action          | Per Minute | Per Hour | Per Day |
|-----------------|------------|----------|---------|
| Public Scans    | 60         | 500      | 5.000   |
| Unlisted Scans  | 60         | 100      | 1.000   |
| Private Scans   | 5          | 50       | 50      |
| Search Requests | 120        | 1.000    | 1.000   |
| Result Retrieve | 120        | 5.000    | 10.000  |

- Has weird community scoring system. Not reliable enough for automated use.


### 1.7 Google Safe Browsing

- Good but hidden behind google developer account.

| Action              | Per Minute | Per Day |
|---------------------|------------|---------|
| Lookup API requests | 1.800      | 10.000  |


### 1.8 MISP

- made sure MISP is an optional feature with a flag and the code is kept separate to make porting to production
without MISP easier.

### 1.9 Shodan - Misp integration

-

### 1.10 AbuseIPDB

- After adding reverse dns lookup to the basic checks, an integration of AbudeIPDB seemed like a good idea.

| Action   | Per Day |
|----------|---------|
| IP check | 1.000   |

Free-friendly options

InternetDB (internetdb.shodan.io) for lightweight IP enrichment (open ports, vulns, tags) without an API key.
Great fallback if you’re wiring Shodan into tools like MISP/pymisp but don’t have a paid plan yet.

source:
https://blog.shodan.io/introducing-the-internetdb-api/

### 1.x Other



### Edge Cases

- verify if shortened url pass by restena dns or not
