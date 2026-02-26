# ASN Risk Assessment Documentation

## Overview
Autonomous System Numbers (ASNs) provide critical infrastructure intelligence for threat assessment. This document explains why certain ASNs like AS13335 (Cloudflare) are flagged as high-risk, the methodology behind ASN-based risk assessment, and how to interpret ASN intelligence in context.

## Understanding ASN Risk Classification

### What is an ASN?
An Autonomous System Number (ASN) is a unique identifier for a network operator on the internet. ASNs are assigned to Internet Service Providers (ISPs), hosting companies, content delivery networks (CDNs), and other network operators.

### Risk vs. Legitimacy
**Important**: ASN risk classification does not indicate that the network operator is malicious. Instead, it identifies infrastructure commonly abused by threat actors due to:
- Ease of access and provisioning
- Anonymity and privacy features
- Lax abuse reporting enforcement
- High-capacity infrastructure suitable for malicious operations

## AS13335 (Cloudflare) Case Study

### Why AS13335 is Flagged
```python
# From metadata_analyzer.py:71
"AS13335",  # Cloudflare (not inherently bad, but often abused)
```

### Cloudflare Characteristics
- **Legitimate Service**: Major CDN and security provider
- **High Abuse Potential**: Easy account creation, free tiers available
- **Anonymization**: Masks true hosting infrastructure behind CDN
- **Global Presence**: Extensive network makes traffic analysis difficult
- **Mixed Reputation**: Used by both legitimate sites and threat actors

### Threat Actor Attraction Factors
```json
{
  "abuse_factors": {
    "easy_provisioning": "Quick account setup with minimal verification",
    "cost_effective": "Free tier available for malicious testing",
    "traffic_masking": "CDN functionality obscures true origin servers",
    "ddos_protection": "Built-in protection useful for C2 infrastructure",
    "global_presence": "Multiple PoPs complicate takedown efforts"
  }
}
```

## ASN Risk Categories

### High-Risk ASNs in Our System
```python
risk_asns = {
    "AS13335",  # Cloudflare (CDN abuse potential)
    "AS16509",  # Amazon (easy EC2 provisioning)
    "AS24940",  # Hetzner (popular for bulletproof hosting)
}
```

### Category Definitions

#### Tier 1: Bulletproof Hosting
- **Characteristics**: Ignore abuse complaints, minimal content restrictions
- **Common Usage**: Malware hosting, command & control servers
- **Examples**: Various Eastern European and offshore providers
- **Risk Level**: Critical

#### Tier 2: Mainstream Cloud Providers
- **Characteristics**: Legitimate services with easy abuse potential
- **Common Usage**: Phishing sites, malware staging, proxy networks
- **Examples**: AS13335 (Cloudflare), AS16509 (Amazon), AS14061 (DigitalOcean)
- **Risk Level**: High

#### Tier 3: Specialized Hosting
- **Characteristics**: Technical hosting with minimal oversight
- **Common Usage**: Technical infrastructure, some legitimate privacy needs
- **Examples**: AS24940 (Hetzner), various VPS providers
- **Risk Level**: Medium-High

#### Tier 4: Traditional ISPs
- **Characteristics**: Residential and business internet providers
- **Common Usage**: Compromised hosts, residential proxies
- **Risk Level**: Medium

## Risk Assessment Methodology

### ASN Intelligence Gathering
```python
def assess_asn_risk(asn):
    risk_factors = {
        "abuse_history": check_abuse_databases(asn),
        "hosting_type": classify_hosting_type(asn),
        "geographic_location": assess_jurisdiction_risk(asn),
        "abuse_response": evaluate_abuse_response_history(asn),
        "legitimate_usage": calculate_legitimate_traffic_ratio(asn)
    }

    return calculate_composite_risk_score(risk_factors)
```

### Multi-Factor Risk Scoring
```json
{
  "asn_risk_assessment": {
    "asn": "AS13335",
    "operator": "Cloudflare, Inc.",
    "risk_factors": {
      "abuse_frequency": 0.7,     // High due to easy abuse
      "takedown_response": 0.3,   // Good response to abuse reports
      "legitimate_usage": 0.9,    // Extensive legitimate usage
      "accessibility": 0.8,       // Very easy to provision resources
      "anonymization": 0.7        // Provides traffic masking
    },
    "composite_score": 65,
    "risk_category": "high_abuse_potential"
  }
}
```

### Contextual Risk Adjustment
```python
def adjust_asn_risk_with_context(base_risk, context_factors):
    adjusted_risk = base_risk

    # Domain age context
    if context_factors.get("domain_age_days", 0) > 365:
        adjusted_risk -= 10  # Established domains less likely to be malicious

    # Multiple ASN diversity
    asn_count = len(context_factors.get("all_asns", []))
    if asn_count > 3:
        adjusted_risk += 5   # High ASN diversity suspicious

    # Certificate validation
    if context_factors.get("valid_ssl_cert"):
        adjusted_risk -= 5   # Valid certificates suggest legitimacy

    # Cross-provider validation
    if context_factors.get("provider_agreement") == "high":
        adjusted_risk -= 10  # High provider agreement reduces uncertainty

    return max(0, min(100, adjusted_risk))
```

## Geographic and Jurisdictional Factors

### Jurisdiction Risk Assessment
```json
{
  "jurisdiction_analysis": {
    "country": "US",
    "regulatory_environment": "strong",
    "law_enforcement_cooperation": "high",
    "abuse_response_mandate": "required",
    "privacy_laws": "balanced",
    "risk_modifier": -5
  }
}
```

### High-Risk Jurisdictions
- **Weak Law Enforcement**: Limited cybercrime prosecution
- **Minimal Regulation**: Few requirements for abuse response
- **Privacy Havens**: Strong privacy laws limiting investigation
- **Economic Factors**: Countries with limited legitimate hosting alternatives

### Low-Risk Jurisdictions
- **Strong Regulation**: Mandatory abuse response procedures
- **Law Enforcement Cooperation**: International cooperation agreements
- **Industry Standards**: Established best practices and oversight
- **Economic Stability**: Stable legitimate hosting ecosystem

## Integration with Threat Assessment

### ASN Risk Contribution
```python
def calculate_asn_threat_contribution(network_topology):
    asn_risk_score = 0
    risk_details = []

    for asn in network_topology.asns:
        asn_risk = assess_individual_asn_risk(asn)

        if asn_risk["score"] > 60:  # High risk threshold
            asn_risk_score += asn_risk["score"] * 0.1  # Weight factor
            risk_details.append({
                "asn": asn,
                "operator": asn_risk["operator"],
                "risk_type": asn_risk["primary_risk_factor"],
                "score": asn_risk["score"]
            })

    return {
        "total_asn_risk": min(50, asn_risk_score),  # Cap contribution
        "risk_details": risk_details,
        "asn_diversity": len(network_topology.asns)
    }
```

### Cross-Validation with Other Indicators
```python
def validate_asn_risk_with_metadata(asn_risk, other_indicators):
    validation_result = {
        "asn_risk_confirmed": False,
        "supporting_evidence": [],
        "contradictory_evidence": []
    }

    # Check for supporting indicators
    if other_indicators.get("new_domain") and asn_risk > 70:
        validation_result["supporting_evidence"].append("New domain on high-risk ASN")
        validation_result["asn_risk_confirmed"] = True

    # Check for contradictory evidence
    if other_indicators.get("established_brand") and asn_risk > 50:
        validation_result["contradictory_evidence"].append("Established brand unlikely to use high-risk hosting")

    # Domain age vs ASN risk correlation
    domain_age = other_indicators.get("domain_age_days", 0)
    if domain_age > 1000 and asn_risk > 60:
        validation_result["contradictory_evidence"].append("Old domain using high-risk ASN suggests legitimate CDN usage")

    return validation_result
```

## Common ASN Analysis Scenarios

### Legitimate CDN Usage (Cloudflare)
```json
{
  "scenario": "legitimate_cdn",
  "asn": "AS13335",
  "indicators": {
    "domain_age": 5000,
    "ssl_certificate": "valid_extended_validation",
    "brand_recognition": "established_company",
    "multiple_asns": ["AS13335", "AS16509"],  // CDN + origin server
    "abuse_reports": 0
  },
  "risk_assessment": "low_despite_high_risk_asn",
  "explanation": "Legitimate enterprise using Cloudflare CDN services"
}
```

### Suspicious New Domain (Cloudflare)
```json
{
  "scenario": "suspicious_new_domain",
  "asn": "AS13335",
  "indicators": {
    "domain_age": 7,
    "ssl_certificate": "domain_validated_only",
    "brand_recognition": "none",
    "single_asn": ["AS13335"],
    "redirect_patterns": "excessive"
  },
  "risk_assessment": "high_risk_confirmed",
  "explanation": "New domain on high-risk ASN with suspicious patterns"
}
```

### Bulletproof Hosting Detection
```json
{
  "scenario": "bulletproof_hosting",
  "asn": "AS12345",  // Hypothetical bulletproof provider
  "indicators": {
    "jurisdiction": "high_risk_country",
    "abuse_response": "historically_poor",
    "hosting_type": "specialized_technical",
    "customer_base": "anonymous_friendly"
  },
  "risk_assessment": "critical",
  "explanation": "Known bulletproof hosting provider"
}
```

## Mitigation and Response Strategies

### Risk-Based Monitoring
```python
def determine_monitoring_strategy(asn_risk_level):
    if asn_risk_level >= 80:
        return {
            "monitoring_frequency": "real_time",
            "additional_checks": ["certificate_monitoring", "content_analysis", "behavioral_monitoring"],
            "alert_threshold": "any_suspicious_activity"
        }
    elif asn_risk_level >= 60:
        return {
            "monitoring_frequency": "hourly",
            "additional_checks": ["periodic_content_scan", "reputation_monitoring"],
            "alert_threshold": "multiple_indicators"
        }
    else:
        return {
            "monitoring_frequency": "daily",
            "additional_checks": ["reputation_monitoring"],
            "alert_threshold": "clear_malicious_activity"
        }
```

### Legitimate Usage Exceptions
```python
def check_legitimate_usage_patterns(asn, context):
    legitimate_patterns = [
        # CDN usage patterns
        {
            "pattern": "established_domain_with_cdn",
            "indicators": ["domain_age > 365", "valid_ev_cert", "multiple_asns"],
            "asn_whitelist": ["AS13335", "AS16509", "AS16625"]  // Major CDNs
        },

        # Enterprise hosting patterns
        {
            "pattern": "enterprise_cloud_usage",
            "indicators": ["corporate_domain", "proper_dns_setup", "security_headers"],
            "asn_whitelist": ["AS16509", "AS8075", "AS15169"]  // Major cloud providers
        }
    ]

    for pattern in legitimate_patterns:
        if matches_pattern(context, pattern) and asn in pattern["asn_whitelist"]:
            return {
                "legitimate_usage": True,
                "pattern_type": pattern["pattern"],
                "risk_reduction": 30
            }

    return {"legitimate_usage": False}
```

## Best Practices

### ASN Intelligence Collection
- Maintain updated ASN-to-operator mappings
- Track abuse complaint response times and quality
- Monitor hosting provider reputation changes
- Analyze temporal patterns in ASN abuse

### Risk Assessment Guidelines
- Always consider ASN risk in context with other indicators
- Account for legitimate usage patterns (CDN, cloud hosting)
- Weight ASN risk based on domain age and other legitimacy indicators
- Regular review and update of ASN risk classifications

### False Positive Mitigation
```python
def mitigate_asn_false_positives(assessment):
    mitigations = []

    # CDN detection
    if is_likely_cdn_usage(assessment):
        mitigations.append({
            "type": "cdn_usage_detected",
            "risk_reduction": 25,
            "explanation": "Legitimate CDN usage pattern detected"
        })

    # Enterprise customer detection
    if has_enterprise_indicators(assessment):
        mitigations.append({
            "type": "enterprise_customer",
            "risk_reduction": 20,
            "explanation": "Enterprise usage patterns suggest legitimacy"
        })

    # Historical reputation
    if has_positive_reputation_history(assessment):
        mitigations.append({
            "type": "positive_history",
            "risk_reduction": 15,
            "explanation": "Positive reputation history"
        })

    return mitigations
```

### Reporting and Documentation
- Clearly distinguish between ASN operator risk and content risk
- Document the reasoning behind ASN risk classifications
- Provide context for risk assessment decisions
- Regular reporting on ASN risk accuracy and false positive rates

This ASN risk assessment framework enables infrastructure-based threat intelligence while minimizing false positives through contextual analysis and legitimate usage pattern recognition.
