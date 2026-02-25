# URLScan.io Analysis Documentation

## Overview
URLScan.io provides comprehensive web security analysis by scanning URLs and websites to detect malicious content, infrastructure threats, and behavioral anomalies. This document explains URLScan.io's data structures, scoring methodologies, and threat indicators.

## Risk Scoring System

### Native Score Range
- **Range**: -100 (legitimate) to 100 (malicious)
- **Score Interpretation**:
  - `-100 to -50`: Highly legitimate/trusted
  - `-49 to -1`: Likely legitimate
  - `0`: Neutral/unknown
  - `1 to 50`: Suspicious
  - `51 to 100`: Malicious

### Verdict System
URLScan.io provides multiple verdict sources:

```json
"verdicts": {
  "urlscan": {
    "score": 45,
    "categories": ["phishing"],
    "brands": ["example-brand"]
  },
  "engines": {
    "malicious": 2,
    "suspicious": 1,
    "benign": 15
  },
  "community": {
    "score": 30,
    "votes": 25
  }
}
```

## Threat Analysis Structure

### Risk Score Calculation
The `threat_analysis.risk_score` field (e.g., 270) represents URLScan.io's internal threat scoring that can exceed the verdict range. This aggregates multiple threat indicators:

```json
"threat_analysis": {
  "risk_score": 270,
  "threat_level": "HIGH",
  "threat_indicators": [
    "threat_list_ips_5",
    "threat_list_countries_1",
    "threat_list_asns_2",
    "threat_list_domains_4",
    "threat_list_servers_2",
    "threat_list_urls_12",
    "threat_list_linkDomains_1",
    "threat_list_certificates_4",
    "threat_list_hashes_10"
  ],
  "malicious_indicators": [],
  "suspicious_patterns": []
}
```

### Threat Indicator Meanings

| Indicator                    | Format        | Meaning                                           |
|------------------------------|---------------|---------------------------------------------------|
| `threat_list_ips_X`          | Number suffix | X IP addresses found in threat intelligence feeds |
| `threat_list_countries_X`    | Number suffix | X countries associated with malicious activity    |
| `threat_list_asns_X`         | Number suffix | X ASNs flagged in threat databases                |
| `threat_list_domains_X`      | Number suffix | X domains found in threat lists                   |
| `threat_list_servers_X`      | Number suffix | X server technologies flagged as suspicious       |
| `threat_list_urls_X`         | Number suffix | X URLs found in malicious URL databases           |
| `threat_list_linkDomains_X`  | Number suffix | X linked domains with threat associations         |
| `threat_list_certificates_X` | Number suffix | X SSL certificates with security issues           |
| `threat_list_hashes_X`       | Number suffix | X file hashes matching malware databases          |

### Threat Level Classification

```json
"threat_level": "MINIMAL|LOW|MEDIUM|HIGH|CRITICAL"
```

- **MINIMAL**: No significant threats detected
- **LOW**: Minor suspicious indicators
- **MEDIUM**: Multiple suspicious patterns
- **HIGH**: Clear malicious indicators
- **CRITICAL**: Confirmed malicious activity

## Network Analysis Data

### Page Information
```json
"page": {
  "ip": "93.184.216.34",
  "domain": "example.com",
  "country": "US",
  "asn": "AS15133",
  "server": "Apache/2.4.41",
  "url": "https://example.com/"
}
```

### Lists Section
```json
"lists": {
  "ips": ["93.184.216.34", "104.16.123.45"],
  "domains": ["example.com", "cdn.example.com"],
  "countries": ["US", "CF"],
  "asns": ["AS15133", "AS13335"],
  "servers": ["Apache/2.4.41", "cloudflare"]
}
```

## Technology Detection (Wappalyzer Integration)

### Technology Stack Analysis
```json
"wappa": {
  "data": [
    {
      "app": "WordPress",
      "categories": [{"name": "CMS"}],
      "confidence": 100,
      "version": "5.8.2"
    },
    {
      "app": "jQuery",
      "categories": [{"name": "JavaScript libraries"}],
      "confidence": 95
    }
  ]
}
```

### Technology Categories
- **CMS**: Content Management Systems
- **Web frameworks**: Backend frameworks
- **JavaScript libraries**: Client-side libraries
- **Web servers**: Server software
- **Analytics**: Tracking and analytics tools
- **CDN**: Content Delivery Networks

## Security Analysis

### Certificate Information
```json
"certificates": [
  {
    "subject": "CN=example.com",
    "issuer": "Let's Encrypt Authority X3",
    "validFrom": "2024-01-01",
    "validTo": "2024-04-01",
    "fingerprint": "sha256:abc123..."
  }
]
```

### Request Analysis
```json
"stats": {
  "requests": 45,
  "dataLength": 2048576,
  "encodedDataLength": 1024288,
  "transferSize": 1234567
}
```

## Behavioral Metadata

### Resource Distribution
```json
"data": {
  "requests": [
    {
      "response": {
        "type": "Document",
        "mimeType": "text/html",
        "status": 200
      }
    }
  ]
}
```

### Performance Metrics
- **Load Time**: Page loading duration
- **Resource Count**: Number of resources loaded
- **Data Transfer**: Total bytes transferred
- **Request Types**: Distribution of resource types

## Integration Notes for Our Tool

### Data Extraction Points
1. **Network Intelligence**: Extract IPs, ASNs, countries, domains from `lists` section
2. **Technology Fingerprinting**: Parse Wappalyzer data for tech stack analysis
3. **Security Assessment**: Analyze certificate validity and security headers
4. **Behavioral Analysis**: Extract request patterns and resource distribution

### Threat Assessment Logic
- Use native `verdicts.urlscan.score` for URLScan-specific threat level
- Parse `threat_indicators` array for specific threat types
- Cross-reference `lists` data with other providers for validation
- Extract `threat_analysis.risk_score` but normalize to standard ranges

### Common Response Scenarios

#### Clean Site Example
```json
{
  "verdicts": {"urlscan": {"score": -25}},
  "threat_analysis": {
    "risk_score": 10,
    "threat_level": "MINIMAL",
    "threat_indicators": []
  }
}
```

#### Suspicious Site Example
```json
{
  "verdicts": {"urlscan": {"score": 35}},
  "threat_analysis": {
    "risk_score": 150,
    "threat_level": "MEDIUM",
    "threat_indicators": ["threat_list_domains_2", "threat_list_ips_1"]
  }
}
```

#### Malicious Site Example
```json
{
  "verdicts": {"urlscan": {"score": 85}},
  "threat_analysis": {
    "risk_score": 270,
    "threat_level": "HIGH",
    "threat_indicators": [
      "threat_list_ips_5",
      "threat_list_urls_12",
      "threat_list_domains_4"
    ]
  }
}
```

## Cross-Validation Considerations

### Reliability Factors
- URLScan.io provides rich metadata but may have false positives
- Technology detection is generally accurate via Wappalyzer
- Network topology data is highly reliable
- Threat scoring should be normalized for cross-provider comparison

### Validation Points
- Cross-check IP/ASN data with other providers
- Validate domain age against WHOIS data
- Compare redirect chains with YARA analysis
- Correlate technology stack with security assessment

## Rate Limits and API Constraints
- Submission rate limits apply
- Analysis completion time varies (10-60 seconds)
- Pro features require authentication
- Free tier has submission quotas

## Error Handling

### Common Error States
```json
{
  "status": "error",
  "message": "Analysis timeout",
  "error_code": 408
}
```

- **404**: URL not found or unreachable
- **408**: Analysis timeout
- **429**: Rate limit exceeded
- **500**: Internal service error

Always check `status` field before processing results.
