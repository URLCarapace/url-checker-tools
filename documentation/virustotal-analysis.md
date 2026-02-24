# VirusTotal Analysis Documentation

## Overview
VirusTotal is a comprehensive malware analysis platform that aggregates results from multiple antivirus engines and security vendors. This document explains VirusTotal's data structures, detection methodologies, and verdict interpretation.

## Detection System

### Engine-Based Analysis
VirusTotal scans URLs and files using 70+ antivirus engines and security vendors:

```json
{
  "stats": {
    "harmless": 71,
    "malicious": 2,
    "suspicious": 3,
    "undetected": 21,
    "timeout": 0
  },
  "total": 97
}
```

### Detection Categories

| Category     | Meaning                                           |
|--------------|---------------------------------------------------|
| `malicious`  | Engine flagged content as definitively malicious  |
| `suspicious` | Engine flagged content as potentially harmful     |
| `harmless`   | Engine analyzed and determined content is safe    |
| `undetected` | Engine found no threats (different from harmless) |
| `timeout`    | Engine analysis timed out                         |

## Verdict Calculation

### Overall Assessment Logic
```json
{
  "verdict": "malicious|suspicious|harmless|unknown",
  "analysis_status": "completed|pending|timeout",
  "confidence": "2+3/97"  // malicious+suspicious/total
}
```

### Verdict Determination Rules
1. **Malicious**: If any engine flags as malicious OR malicious count > 0
2. **Suspicious**: If suspicious count > 0 AND no malicious detections
3. **Harmless**: If majority of engines report harmless
4. **Unknown**: If analysis incomplete or insufficient data

## Engine-Specific Results

### Individual Engine Response
```json
{
  "scans": {
    "Avast": {
      "detected": true,
      "version": "22.11.7701.0",
      "result": "URL:Phishing",
      "update": "20241201"
    },
    "Bitdefender": {
      "detected": false,
      "version": "7.90982",
      "result": null,
      "update": "20241201"
    }
  }
}
```

### Engine Categories
- **Major AV Vendors**: Avast, Bitdefender, Kaspersky, McAfee, Norton
- **Cloud Security**: Microsoft Defender, Google Safebrowsing
- **Specialized Detectors**: Phishing detection, malware family classification
- **Threat Intelligence**: Feeds from security research organizations

## URL Analysis Response Structure

### Complete Response Example
```json
{
  "data": {
    "type": "analysis",
    "id": "u-abc123def456",
    "attributes": {
      "stats": {
        "harmless": 71,
        "malicious": 0,
        "suspicious": 0,
        "undetected": 26,
        "timeout": 0
      },
      "url": "https://example.com",
      "date": 1701234567,
      "status": "completed"
    },
    "links": {
      "self": "https://www.virustotal.com/api/v3/analyses/u-abc123def456"
    }
  }
}
```

### URL Report Structure
```json
{
  "data": {
    "type": "url",
    "id": "base64-encoded-url",
    "attributes": {
      "url": "https://example.com",
      "last_analysis_stats": {
        "harmless": 71,
        "malicious": 0,
        "suspicious": 0,
        "undetected": 26,
        "timeout": 0
      },
      "last_analysis_date": 1701234567,
      "reputation": 0,
      "total_votes": {
        "harmless": 15,
        "malicious": 0
      }
    }
  }
}
```

## Threat Classification

### Malware Categories
Common detection categories from engines:

| Category       | Description                         |
|----------------|-------------------------------------|
| `URL:Phishing` | Phishing/credential harvesting site |
| `URL:Malware`  | Site hosting malware                |
| `Adware`       | Potentially unwanted advertising    |
| `PUA`          | Potentially Unwanted Application    |
| `Trojan`       | Trojan horse malware                |
| `Ransomware`   | File-encrypting malware             |

### Reputation Scoring
```json
{
  "reputation": -5,  // Range: -100 to +100
  "total_votes": {
    "harmless": 25,
    "malicious": 2
  },
  "community_score": 23  // harmless - malicious votes
}
```

## Historical Analysis

### Analysis History
```json
{
  "last_analysis_date": 1701234567,
  "first_submission_date": 1650123456,
  "times_submitted": 45,
  "last_submission_date": 1701234567
}
```

### Trend Analysis
- **Submission Frequency**: How often URL has been analyzed
- **Detection Trends**: Changes in detection over time
- **Engine Agreement**: Consistency across different analysis dates

## Integration Notes for Our Tool

### Data Extraction Strategy
1. **Primary Verdict**: Use `last_analysis_stats` for current threat assessment
2. **Confidence Calculation**: Format as "malicious+suspicious/total"
3. **Engine Details**: Extract specific engine results for detailed analysis
4. **Reputation Context**: Include community voting and reputation score

### Threat Assessment Logic
```python
def assess_virustotal_threat(stats):
    total = sum(stats.values())
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)

    if malicious > 0:
        return "MALICIOUS", f"{malicious}+{suspicious}/{total}"
    elif suspicious > 0:
        return "SUSPICIOUS", f"{malicious}+{suspicious}/{total}"
    elif stats.get('harmless', 0) > total * 0.7:
        return "HARMLESS", f"{stats['harmless']} clean engines"
    else:
        return "UNKNOWN", "Insufficient detection data"
```

### UI URL Generation
```python
ui_url = f"https://www.virustotal.com/gui/url/{base64_url_id}"
```

## Common Response Scenarios

### Clean URL (Example.com)
```json
{
  "stats": {"harmless": 71, "malicious": 0, "suspicious": 0, "undetected": 26},
  "verdict": "harmless",
  "confidence": "0+0/97"
}
```

### Suspicious URL
```json
{
  "stats": {"harmless": 50, "malicious": 0, "suspicious": 5, "undetected": 42},
  "verdict": "suspicious",
  "confidence": "0+5/97"
}
```

### Malicious URL
```json
{
  "stats": {"harmless": 30, "malicious": 15, "suspicious": 8, "undetected": 44},
  "verdict": "malicious",
  "confidence": "15+8/97"
}
```

## Cross-Validation Considerations

### Reliability Factors
- **High Accuracy**: Multiple engine consensus provides strong confidence
- **False Positives**: Some engines may flag legitimate sites
- **Detection Lag**: New threats may not be detected by all engines
- **Regional Variations**: Some engines better at detecting region-specific threats

### Validation Points
- Cross-check malicious verdicts with URLScan.io threat analysis
- Validate suspicious flags against YARA rule matches
- Compare engine consensus with community reputation
- Use detection timeline for trend analysis

### Confidence Scoring
- **High Confidence**: >5 engines agree on verdict
- **Medium Confidence**: 2-5 engines detect threat
- **Low Confidence**: Single engine detection
- **Disputed**: Conflicting verdicts from reputable engines

## API Rate Limits

### Request Limits
- **Free API**: 4 requests/minute, 1000/month
- **Premium**: Higher limits based on subscription tier
- **Bulk Operations**: Special endpoints for multiple URLs

### Usage Optimization
- Cache results for frequently checked URLs
- Use batch endpoints when available
- Implement exponential backoff for rate limit errors

## Error Handling

### Common Error Responses
```json
{
  "error": {
    "code": "QuotaExceededError",
    "message": "API key quota exceeded"
  }
}
```

### Error Types
- `QuotaExceededError`: API rate limit reached
- `InvalidArgumentError`: Malformed URL or parameters
- `NotFoundError`: URL not yet analyzed
- `AuthenticationRequiredError`: Invalid or missing API key

### Retry Logic
```python
def handle_vt_error(response):
    if response.status_code == 429:  # Rate limited
        return "retry_after_delay"
    elif response.status_code == 404:  # Not found
        return "submit_for_analysis"
    elif response.status_code == 403:  # Quota exceeded
        return "api_limit_reached"
    else:
        return "general_error"
```

## Lookyloo Integration Context

When VirusTotal results are obtained through Lookyloo, the data structure may be slightly different:

```json
{
  "virustotal": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 70,
    "undetected": 26,
    "timeout": 0,
    "permalink": "https://www.virustotal.com/gui/url/..."
  }
}
```

This provides the same statistical information but in a simplified format suitable for cross-provider analysis.
