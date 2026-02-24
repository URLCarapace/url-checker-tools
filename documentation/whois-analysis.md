# WHOIS Analysis Documentation

## Overview
WHOIS provides domain registration information that is crucial for assessing domain legitimacy, age, and potential risk indicators. This document explains WHOIS data interpretation, domain assessment methodologies, and integration patterns for threat analysis.

## WHOIS Data Structure

### Core Domain Information
```json
{
  "domain_name": "example.com",
  "registrar": "Internet Assigned Numbers Authority",
  "creation_date": "1992-01-01T00:00:00",
  "expiration_date": "2025-01-01T00:00:00",
  "updated_date": "2023-08-15T14:30:00",
  "status": ["clientTransferProhibited", "serverDeleteProhibited"]
}
```

### Registrant Information
```json
{
  "registrant": {
    "name": "Domain Administrator",
    "organization": "Example Organization",
    "country": "US",
    "privacy_protected": false
  },
  "admin_contact": {
    "email": "admin@example.com",
    "privacy_protected": true
  },
  "tech_contact": {
    "privacy_protected": true
  }
}
```

### Name Servers
```json
{
  "name_servers": [
    "ns1.example.com",
    "ns2.example.com"
  ],
  "dnssec": "unsigned"
}
```

## Domain Age Analysis

### Age Calculation
```python
def calculate_domain_age(creation_date):
    if not creation_date:
        return None

    today = datetime.now()
    age_delta = today - creation_date
    return age_delta.days
```

### Age-Based Risk Assessment
| Age Range   | Risk Level | Characteristics                        |
|-------------|------------|----------------------------------------|
| 0-30 days   | Very High  | Newly registered, high fraud potential |
| 31-90 days  | High       | Recently created, monitor closely      |
| 91-365 days | Medium     | Young domain, some legitimacy          |
| 1-2 years   | Low-Medium | Establishing reputation                |
| 2+ years    | Low        | Established domain                     |
| 10+ years   | Very Low   | Well-established, likely legitimate    |

### Age Confidence Factors
```json
{
  "age_assessment": {
    "domain_age_days": 12291,
    "age_years": 33.6,
    "risk_category": "very_low",
    "confidence_factors": [
      "Well-established domain (30+ years)",
      "Consistent registration history",
      "Major organization registrant"
    ]
  }
}
```

## Registrar Analysis

### Registrar Risk Indicators
```json
{
  "registrar_analysis": {
    "registrar": "Internet Assigned Numbers Authority",
    "registrar_reputation": "high",
    "common_abuse_registrar": false,
    "geographic_location": "US",
    "accreditation": "ICANN_ACCREDITED"
  }
}
```

### High-Risk Registrar Patterns
- **Bullet-proof Hosting**: Registrars known for ignoring abuse complaints
- **Frequent Domain Churning**: Registrars with high domain creation/deletion rates
- **Lax Verification**: Minimal identity verification requirements
- **Geographic Flags**: Registrars in jurisdictions with weak enforcement

### Legitimate Registrar Indicators
- **ICANN Accreditation**: Officially recognized registrar status
- **Abuse Response**: Active abuse complaint handling
- **Corporate Clients**: Used by major legitimate organizations
- **Transparency**: Clear contact information and policies

## Domain Status Analysis

### Status Code Meanings
| Status Code                | Meaning                        | Risk Implication           |
|----------------------------|--------------------------------|----------------------------|
| `clientDeleteProhibited`   | Registrant protected deletion  | Legitimate protection      |
| `clientTransferProhibited` | Transfer restrictions in place | Normal security measure    |
| `clientUpdateProhibited`   | Update restrictions            | Enhanced security          |
| `serverHold`               | Registry suspension            | Potential abuse/violations |
| `pendingDelete`            | Scheduled for deletion         | Domain abandonment         |
| `redemptionPeriod`         | Grace period after expiration  | Possible domain drop       |

### Suspicious Status Patterns
```python
def analyze_domain_status(status_list):
    risk_indicators = []

    if "serverHold" in status_list:
        risk_indicators.append("Registry suspension - possible violations")

    if "pendingDelete" in status_list:
        risk_indicators.append("Domain scheduled for deletion")

    if len(status_list) == 0:
        risk_indicators.append("No protection status - vulnerable to hijacking")

    return risk_indicators
```

## Privacy Protection Analysis

### Privacy Service Detection
```json
{
  "privacy_analysis": {
    "whois_privacy_enabled": true,
    "privacy_service": "Domains by Proxy LLC",
    "masked_fields": ["registrant", "admin_contact", "tech_contact"],
    "legitimate_privacy_use": true
  }
}
```

### Privacy vs. Abuse Correlation
- **Legitimate Privacy**: Personal websites, small businesses
- **Suspicious Privacy**: Combined with other risk factors
- **Privacy Services**: Evaluate reputation of privacy provider
- **Complete Masking**: All contact information hidden

## Integration Notes for Our Tool

### Data Processing Pipeline
```python
def process_whois_data(whois_response):
    analysis = {
        "is_active": whois_response.get("is_active", False),
        "domain_age_days": calculate_domain_age(whois_response.get("creation_date")),
        "registrar": whois_response.get("registrar"),
        "risk_assessment": assess_domain_risk(whois_response)
    }
    return analysis
```

### Risk Score Contribution
```python
def calculate_whois_risk_score(whois_data):
    base_score = 50  # Neutral

    age_days = whois_data.get("domain_age_days", 0)

    # Age-based scoring
    if age_days < 30:
        base_score += 40  # Very high risk
    elif age_days < 90:
        base_score += 25  # High risk
    elif age_days < 365:
        base_score += 10  # Medium risk
    elif age_days > 3650:  # 10+ years
        base_score -= 20   # Very low risk

    # Registrar-based scoring
    if is_high_risk_registrar(whois_data.get("registrar")):
        base_score += 15

    # Privacy protection context
    if excessive_privacy_protection(whois_data):
        base_score += 10

    return min(100, max(0, base_score))
```

### Cross-Validation Applications
- **Domain Age vs. SSL Certificate Age**: Inconsistencies may indicate domain hijacking
- **Registrar vs. Hosting Provider**: Mismatches might suggest proxy/CDN usage
- **Geographic Correlation**: Compare registrant country with hosting location

## Threat Intelligence Integration

### Threat Result Creation
```python
def create_whois_threat_result(target, whois_response):
    is_active = whois_response.get("is_active", False)

    if not is_active:
        return ThreatIntelligenceResult(
            provider=ProviderType.WHOIS,
            target=target,
            status=ThreatStatus.ERROR,
            is_threat_detected=False,
            threat_type="domain_inactive",
            error_message="Domain is inactive or not found"
        )

    # Build confidence information
    confidence_info = []
    age_days = whois_response.get("domain_age_days")
    if age_days:
        confidence_info.append(f"age: {age_days} days")

    registrar = whois_response.get("registrar")
    if registrar:
        confidence_info.append(f"registrar: {registrar}")

    return ThreatIntelligenceResult(
        provider=ProviderType.WHOIS,
        target=target,
        status=ThreatStatus.CLEAN,  # WHOIS doesn't detect threats
        is_threat_detected=False,
        confidence="; ".join(confidence_info) if confidence_info else None,
        raw_response=whois_response
    )
```

## Common Analysis Scenarios

### Established Legitimate Domain
```json
{
  "domain": "example.com",
  "age_days": 12291,
  "registrar": "Internet Assigned Numbers Authority",
  "risk_score": 10,
  "confidence_factors": ["Well-established (33+ years)", "Reputable registrar"]
}
```

### New Suspicious Domain
```json
{
  "domain": "example-phishing.com",
  "age_days": 15,
  "registrar": "Cheap Domains LLC",
  "privacy_protected": true,
  "risk_score": 85,
  "risk_indicators": ["Very new domain", "High-risk registrar", "Full privacy protection"]
}
```

### Domain Squatting Detection
```python
def detect_domain_squatting(target_domain, legitimate_domains):
    squatting_indicators = []

    for legit_domain in legitimate_domains:
        similarity = calculate_similarity(target_domain, legit_domain)
        if similarity > 0.8:
            squatting_indicators.append(f"Similar to {legit_domain} (similarity: {similarity})")

    return squatting_indicators
```

## Error Handling

### WHOIS Lookup Failures
```json
{
  "is_active": false,
  "error_type": "whois_timeout",
  "message": "WHOIS server did not respond",
  "fallback_data": null
}
```

### Common Error Scenarios
- **Domain Not Found**: Domain doesn't exist in registry
- **WHOIS Server Timeout**: Registry server unavailable
- **Rate Limiting**: Too many queries in short period
- **Privacy Block**: Complete information masking

### Fallback Strategies
```python
def handle_whois_failure(domain, error_type):
    fallback_data = {
        "is_active": None,  # Unknown status
        "domain_age_days": None,
        "registrar": None,
        "confidence": "whois_lookup_failed"
    }

    # Try alternative WHOIS sources
    if error_type == "timeout":
        return try_alternative_whois_server(domain)

    return fallback_data
```

## Historical Analysis

### Domain History Tracking
```json
{
  "historical_data": {
    "previous_owners": ["Original Registrant", "Current Owner"],
    "ownership_changes": 1,
    "registrar_changes": 0,
    "last_transfer": "2010-05-15",
    "expiration_lapses": 0
  }
}
```

### Change Detection Indicators
- **Recent Ownership Changes**: May indicate domain sale or compromise
- **Frequent Registrar Changes**: Possible evasion tactics
- **Expiration/Renewal Patterns**: Domain drop catching attempts
- **Contact Information Changes**: Ownership verification issues

## Best Practices

### Query Optimization
- Implement caching for frequently checked domains
- Respect WHOIS server rate limits
- Use appropriate WHOIS server for TLD
- Handle internationalized domain names properly

### Data Validation
- Cross-check creation dates across multiple sources
- Verify registrar information with ICANN database
- Validate contact information format and consistency
- Compare WHOIS data with DNS records for consistency

### Privacy Considerations
- Respect privacy protection services
- Don't expose personal information in logs
- Follow applicable data protection regulations
- Implement data retention policies

This WHOIS analysis framework provides foundational domain intelligence that enhances threat assessment when combined with other providers' technical analysis capabilities.
