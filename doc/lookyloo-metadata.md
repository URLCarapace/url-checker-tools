# Lookyloo Metadata Documentation

## Overview
Lookyloo is a web forensics platform that captures comprehensive behavioral metadata about websites through browser automation. In our tool, Lookyloo serves exclusively as a **metadata provider** for cross-validation, not for threat detection. This document explains Lookyloo's data structures and behavioral analysis capabilities.

## Role Transformation
**Important**: As of the recent refactoring, Lookyloo is **no longer used for threat detection**. Instead, it provides rich behavioral metadata that is cross-validated against other threat intelligence providers.

## Behavioral Metadata Structure

### Network Topology Analysis
```json
{
  "network_topology": {
    "unique_hostnames": 5,
    "unique_ips": 3,
    "hostname_list": ["example.com", "cdn.example.com", "tracker.ads.com"],
    "ip_addresses": ["93.184.216.34", "104.16.123.45", "192.168.1.1"],
    "countries": ["US", "CF"],
    "asn_distribution": {
      "AS15133": ["93.184.216.34"],
      "AS13335": ["104.16.123.45"]
    }
  }
}
```

### Page Structure Analysis
```json
{
  "page_structure": {
    "total_resources": 45,
    "resource_breakdown": {
      "documents": 1,
      "scripts": 12,
      "stylesheets": 8,
      "images": 15,
      "fonts": 4,
      "xhr": 5
    },
    "page_size": 2048576,
    "dom_complexity": {
      "total_nodes": 1250,
      "iframe_count": 2,
      "form_count": 1
    }
  }
}
```

### Redirect Behavior Analysis
```json
{
  "redirect_behavior": {
    "redirect_count": 3,
    "redirect_chain": [
      "http://example.com",
      "https://example.com",
      "https://www.example.com",
      "https://www.example.com/home"
    ],
    "redirect_types": ["301", "302"],
    "cross_domain_redirects": 0,
    "suspicious_patterns": []
  }
}
```

### Resource Analysis
```json
{
  "resource_analysis": {
    "external_domains": 8,
    "third_party_requests": 25,
    "cdn_usage": ["cloudflare", "amazon_cloudfront"],
    "tracking_domains": ["google-analytics.com", "facebook.com"],
    "advertising_networks": ["doubleclick.net", "adsystem.com"],
    "security_headers": {
      "csp_present": true,
      "hsts_present": false,
      "x_frame_options": "DENY"
    }
  }
}
```

### Timing Analysis
```json
{
  "timing_analysis": {
    "page_load_time": 2.45,
    "first_contentful_paint": 1.2,
    "dom_content_loaded": 1.8,
    "resource_load_distribution": {
      "0-1s": 15,
      "1-3s": 20,
      "3-5s": 8,
      ">5s": 2
    }
  }
}
```

## Capture Analysis Data

### Raw Capture Information
```json
{
  "analysis_data": {
    "uuid": "108c819f-9192-4784-bfd3-c4ae66596041",
    "url": "https://example.com",
    "status": "completed",
    "capture_time": "2024-12-01T15:30:45Z",
    "user_agent": "Mozilla/5.0 ...",
    "capture_settings": {
      "browser": "chromium",
      "viewport": "1920x1080",
      "javascript_enabled": true
    }
  }
}
```

### Security Module Results
```json
{
  "security_modules": {
    "phishtank": {
      "status": "clean",
      "last_checked": "2024-12-01T15:31:00Z"
    },
    "urlhaus": {
      "status": "clean",
      "matches": 0
    },
    "urlscan": {
      "status": "available",
      "analysis_id": "abc123def456"
    },
    "virustotal": {
      "status": "clean",
      "detection_ratio": "0/97"
    }
  }
}
```

## Metadata Extraction Methods

### Network Data Extraction
```python
def extract_network_metadata(lookyloo_response):
    analysis_data = lookyloo_response.get("analysis_data", {})

    network_metadata = {
        "hostnames": analysis_data.get("hostnames", []),
        "ip_addresses": analysis_data.get("ip_addresses", []),
        "countries": analysis_data.get("countries", []),
        "redirects": analysis_data.get("redirects", [])
    }

    return network_metadata
```

### Behavioral Pattern Detection
```python
def analyze_redirect_patterns(redirect_chain):
    patterns = []

    if len(redirect_chain) > 5:
        patterns.append("excessive_redirects")

    for i, url in enumerate(redirect_chain[:-1]):
        next_url = redirect_chain[i + 1]
        if get_domain(url) != get_domain(next_url):
            patterns.append("cross_domain_redirect")

    return patterns
```

## Cross-Validation Applications

### Network Topology Validation
- **IP Address Consistency**: Compare Lookyloo's detected IPs with URLScan.io results
- **ASN Correlation**: Validate ASN information against WHOIS data
- **Geographic Distribution**: Cross-check country data with other providers

### Redirect Chain Validation
- **YARA Comparison**: Validate redirect count and patterns against YARA analysis
- **URLScan Correlation**: Compare final URLs and redirect behavior
- **Suspicious Pattern Detection**: Identify discrepancies that may indicate cloaking

### Resource Loading Patterns
- **Third-party Dependencies**: Analyze external domain usage for risk assessment
- **CDN Validation**: Verify legitimate CDN usage vs. suspicious hosting
- **Technology Stack Correlation**: Cross-check with URLScan.io technology detection

## Confidence Scoring Contributions

### Reliability Factors
```json
{
  "confidence_factors": {
    "capture_completeness": 0.95,  // Successful resource loading percentage
    "network_consistency": 0.8,   // Agreement with other providers
    "behavioral_normalcy": 0.9,   // Typical website behavior patterns
    "data_freshness": 0.85        // Recent capture vs. cache age
  }
}
```

### Quality Indicators
- **Complete Capture**: All resources loaded successfully
- **No JavaScript Errors**: Clean execution environment
- **Standard Behavior**: Typical redirect and loading patterns
- **Security Headers**: Presence of standard security measures

## Integration Notes for Our Tool

### Data Processing Pipeline
1. **Capture Submission**: Submit URL to Lookyloo for analysis
2. **Status Monitoring**: Poll capture status until completion
3. **Metadata Extraction**: Parse behavioral data from response
4. **Cross-Validation**: Compare with other provider results
5. **Consistency Scoring**: Calculate agreement levels

### Metadata Normalization
```python
def normalize_lookyloo_metadata(response):
    return {
        "network_topology": extract_network_data(response),
        "resource_analysis": extract_resource_data(response),
        "redirect_behavior": extract_redirect_data(response),
        "timing_metrics": extract_timing_data(response)
    }
```

### Anomaly Detection
```python
def detect_behavioral_anomalies(metadata):
    anomalies = []

    if metadata["redirect_behavior"]["redirect_count"] > 5:
        anomalies.append("excessive_redirects")

    if len(metadata["resource_analysis"]["external_domains"]) > 20:
        anomalies.append("high_external_dependency")

    if metadata["timing_analysis"]["page_load_time"] > 10:
        anomalies.append("slow_loading")

    return anomalies
```

## Common Metadata Scenarios

### Clean Website Example
```json
{
  "network_topology": {"unique_hostnames": 2, "unique_ips": 1},
  "redirect_behavior": {"redirect_count": 1, "suspicious_patterns": []},
  "resource_analysis": {"external_domains": 3, "cdn_usage": ["cloudflare"]},
  "confidence_score": 0.95
}
```

### Suspicious Website Example
```json
{
  "network_topology": {"unique_hostnames": 15, "unique_ips": 8},
  "redirect_behavior": {"redirect_count": 7, "suspicious_patterns": ["cross_domain_redirect"]},
  "resource_analysis": {"external_domains": 25, "tracking_domains": 10},
  "confidence_score": 0.3
}
```

## Error Handling

### Capture Failures
```json
{
  "status": "error",
  "error_type": "capture_timeout",
  "message": "Website did not respond within timeout period",
  "partial_data": true
}
```

### Common Error Types
- `capture_timeout`: Website took too long to load
- `connection_refused`: Website refused connection
- `dns_resolution_failed`: Domain name could not be resolved
- `ssl_handshake_failed`: HTTPS certificate issues

### Partial Data Handling
```python
def handle_partial_capture(response):
    if response.get("partial_data"):
        # Extract what metadata is available
        available_data = extract_available_metadata(response)
        # Lower confidence score for incomplete data
        confidence_penalty = 0.5
        return available_data, confidence_penalty

    return process_complete_capture(response), 1.0
```

## Rate Limits and Performance

### Capture Constraints
- Analysis time: 30-120 seconds per URL
- Queue position affects wait time
- Complex sites take longer to analyze
- Some sites may require multiple attempts

### Optimization Strategies
- Submit captures early in analysis pipeline
- Monitor queue status and adjust timing
- Cache results to avoid duplicate captures
- Handle timeouts gracefully with fallback metadata

## API Integration Details

### Capture Submission
```python
def submit_lookyloo_capture(url):
    response = lookyloo_client.submit(url)
    capture_uuid = response.get("uuid")
    return capture_uuid
```

### Status Monitoring
```python
def wait_for_completion(uuid, max_attempts=10):
    for attempt in range(max_attempts):
        status = lookyloo_client.get_status(uuid)
        if status["status_code"] == 1:  # Complete
            return lookyloo_client.get_result(uuid)
        time.sleep(10)

    raise TimeoutError("Capture did not complete in time")
```

This metadata-focused approach allows Lookyloo to contribute valuable behavioral intelligence for cross-validation without the reliability issues associated with its threat detection capabilities.
