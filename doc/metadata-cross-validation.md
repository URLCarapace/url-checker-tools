# Metadata Cross-Validation Documentation

## Overview
Cross-provider metadata validation is a critical component for improving threat assessment accuracy. This document explains the methodology for comparing data across multiple threat intelligence providers, calculating consistency scores, and identifying anomalies that may indicate threats or false positives.

## Cross-Validation Framework

### Validation Architecture
```python
class MetadataAnalyzer:
    def analyze(self, results: List[ThreatIntelligenceResult]) -> MetadataAnalysis:
        # Extract structured metadata from each provider
        network_topology = self._extract_network_topology(results)
        technology_stack = self._extract_technology_stack(results)
        behavioral_metadata = self._extract_behavioral_metadata(results)

        # Cross-validate data consistency
        consistency_scores = self._calculate_consistency_scores(results)

        # Identify anomalies and risk indicators
        anomalies = self._identify_anomalies(network_topology, technology_stack, behavioral_metadata)
        risk_indicators = self._assess_risk_indicators(network_topology, technology_stack, behavioral_metadata)

        # Calculate overall confidence
        confidence_score = self._calculate_confidence_score(consistency_scores)

        return MetadataAnalysis(...)
```

## Consistency Scoring System

### Consistency Levels
```python
class ConsistencyLevel(Enum):
    HIGH = "high"          # >80% agreement
    MEDIUM = "medium"      # 60-80% agreement
    LOW = "low"           # 40-60% agreement
    INCONSISTENT = "inconsistent"  # <40% agreement
```

### Cross-Validation Categories
```json
{
  "consistency_scores": {
    "network_topology": "high",
    "redirect_chain": "high",
    "technology_stack": "medium",
    "behavioral_patterns": "low"
  }
}
```

## Network Topology Validation

### IP Address Correlation
```python
def validate_ip_addresses(results):
    ip_sources = {}

    for result in results:
        provider = result.provider.value
        ips = extract_ips_from_result(result)
        ip_sources[provider] = set(ips)

    # Calculate agreement percentage
    if len(ip_sources) < 2:
        return ConsistencyLevel.LOW, "Insufficient data sources"

    common_ips = set.intersection(*ip_sources.values())
    all_ips = set.union(*ip_sources.values())

    agreement = len(common_ips) / len(all_ips) if all_ips else 0

    if agreement >= 0.8:
        return ConsistencyLevel.HIGH, f"{len(common_ips)}/{len(all_ips)} IPs consistent"
    elif agreement >= 0.6:
        return ConsistencyLevel.MEDIUM, f"Partial IP consistency ({agreement:.1%})"
    else:
        return ConsistencyLevel.LOW, f"Low IP agreement ({agreement:.1%})"
```

### ASN Validation
```python
def validate_asn_data(urlscan_result, lookyloo_result):
    urlscan_asns = extract_asns(urlscan_result)
    lookyloo_asns = extract_asns(lookyloo_result)

    validation_result = {
        "urlscan_asns": urlscan_asns,
        "lookyloo_asns": lookyloo_asns,
        "common_asns": list(set(urlscan_asns) & set(lookyloo_asns)),
        "discrepancies": list(set(urlscan_asns) ^ set(lookyloo_asns))
    }

    return validation_result
```

### Geographic Correlation
```json
{
  "geographic_validation": {
    "urlscan_countries": ["US", "CF"],
    "lookyloo_countries": ["US"],
    "consistency": "medium",
    "discrepancies": ["CF"],
    "explanation": "URLScan detected additional Cloudflare presence"
  }
}
```

## Redirect Chain Validation

### Redirect Consistency Analysis
```python
def validate_redirect_chains(yara_redirects, lookyloo_redirects, urlscan_redirects):
    chains = {
        "yara": yara_redirects,
        "lookyloo": lookyloo_redirects,
        "urlscan": urlscan_redirects
    }

    # Compare final URLs
    final_urls = {provider: chain[-1] if chain else None for provider, chain in chains.items()}
    unique_finals = set(url for url in final_urls.values() if url)

    # Compare redirect counts
    redirect_counts = {provider: len(chain) for provider, chain in chains.items()}

    consistency = {
        "final_url_agreement": len(unique_finals) == 1,
        "redirect_count_variance": max(redirect_counts.values()) - min(redirect_counts.values()),
        "chains": chains,
        "assessment": determine_redirect_consistency(final_urls, redirect_counts)
    }

    return consistency
```

### Suspicious Pattern Cross-Check
```python
def cross_validate_suspicious_patterns(results):
    pattern_detections = {}

    for result in results:
        provider = result.provider.value
        patterns = extract_suspicious_patterns(result)
        pattern_detections[provider] = patterns

    # Find patterns detected by multiple providers
    common_patterns = find_common_elements(pattern_detections.values())

    # Identify provider-specific detections
    unique_patterns = find_unique_elements(pattern_detections)

    return {
        "common_patterns": common_patterns,
        "provider_specific": unique_patterns,
        "validation_strength": calculate_pattern_validation_strength(pattern_detections)
    }
```

## Technology Stack Validation

### Server Technology Correlation
```python
def validate_technology_stack(urlscan_tech, lookyloo_tech):
    validation = {
        "servers": {
            "urlscan": urlscan_tech.servers,
            "lookyloo": lookyloo_tech.servers,
            "agreement": bool(set(urlscan_tech.servers) & set(lookyloo_tech.servers))
        },
        "frameworks": {
            "urlscan": urlscan_tech.frameworks,
            "agreement_level": calculate_tech_agreement(urlscan_tech.frameworks, [])
        },
        "overall_consistency": determine_tech_consistency(urlscan_tech, lookyloo_tech)
    }

    return validation
```

### CDN and Infrastructure Analysis
```json
{
  "infrastructure_validation": {
    "cdn_providers": {
      "urlscan": ["cloudflare"],
      "lookyloo": ["cloudflare"],
      "consistency": "high"
    },
    "hosting_analysis": {
      "primary_provider": "Cloudflare",
      "secondary_providers": [],
      "infrastructure_type": "CDN"
    }
  }
}
```

## Behavioral Metadata Validation

### Request Pattern Analysis
```python
def validate_behavioral_patterns(results):
    behavioral_data = {}

    for result in results:
        if result.provider in [ProviderType.URLSCAN, ProviderType.LOOKYLOO]:
            behavioral_data[result.provider.value] = extract_behavioral_metadata(result)

    validation = {
        "request_counts": compare_request_counts(behavioral_data),
        "external_domains": validate_external_domains(behavioral_data),
        "resource_distribution": compare_resource_types(behavioral_data),
        "loading_patterns": analyze_loading_consistency(behavioral_data)
    }

    return validation
```

### Performance Metrics Cross-Check
```json
{
  "performance_validation": {
    "urlscan_metrics": {
      "total_requests": 45,
      "load_time": 2.3,
      "data_transfer": 1024000
    },
    "lookyloo_metrics": {
      "total_requests": 47,
      "load_time": 2.1,
      "external_domains": 8
    },
    "consistency_assessment": "high",
    "variance_analysis": {
      "request_count_diff": 2,
      "load_time_diff": 0.2,
      "acceptable_variance": true
    }
  }
}
```

## Anomaly Detection

### Network Anomalies
```python
def identify_network_anomalies(network_topology):
    anomalies = []

    # Geographic diversity anomaly
    if len(network_topology.countries) > 3:
        anomalies.append(f"High geographic diversity: {len(network_topology.countries)} countries")

    # ASN diversity anomaly
    if len(network_topology.asns) > 5:
        anomalies.append(f"High ASN diversity: {len(network_topology.asns)} ASNs")

    # Redirect chain anomaly
    if len(network_topology.redirect_chain) > 8:
        anomalies.append(f"Excessive redirects: {len(network_topology.redirect_chain)}")

    return anomalies
```

### Behavioral Anomalies
```python
def identify_behavioral_anomalies(behavioral_metadata):
    anomalies = []

    # Request volume anomaly
    if behavioral_metadata.request_count and behavioral_metadata.request_count > 100:
        anomalies.append(f"High request count: {behavioral_metadata.request_count}")

    # External dependency anomaly
    if len(behavioral_metadata.external_domains) > 20:
        anomalies.append(f"High external domain count: {len(behavioral_metadata.external_domains)}")

    # Resource size anomaly
    if behavioral_metadata.total_size and behavioral_metadata.total_size > 10 * 1024 * 1024:  # 10MB
        anomalies.append(f"Large page size: {behavioral_metadata.total_size / (1024*1024):.1f}MB")

    return anomalies
```

### Provider Disagreement Detection
```python
def detect_provider_disagreements(results):
    disagreements = []

    # Threat detection disagreements
    threat_verdicts = {result.provider.value: result.is_threat_detected for result in results}

    if len(set(threat_verdicts.values())) > 1:
        disagreements.append({
            "type": "threat_detection_disagreement",
            "details": threat_verdicts,
            "severity": "high"
        })

    # Metadata consistency disagreements
    network_data = extract_network_data_by_provider(results)

    for field in ["final_url", "primary_ip", "main_domain"]:
        field_values = {provider: data.get(field) for provider, data in network_data.items()}
        unique_values = set(v for v in field_values.values() if v)

        if len(unique_values) > 1:
            disagreements.append({
                "type": f"{field}_disagreement",
                "details": field_values,
                "severity": "medium"
            })

    return disagreements
```

## Risk Assessment Integration

### Risk Indicator Analysis
```python
def assess_cross_validated_risks(network_topology, technology_stack, behavioral_metadata):
    risks = []

    # Infrastructure-based risks
    for asn in network_topology.asns:
        if asn in HIGH_RISK_ASNS:
            risk_score = calculate_asn_risk_score(asn)
            risks.append({
                "type": "infrastructure_risk",
                "indicator": f"High-risk ASN: {asn}",
                "score": risk_score,
                "mitigation": "Monitor for abuse patterns"
            })

    # Technology-based risks
    for server in technology_stack.servers:
        if is_outdated_technology(server):
            risks.append({
                "type": "technology_risk",
                "indicator": f"Outdated technology: {server}",
                "score": 30,
                "mitigation": "Check for known vulnerabilities"
            })

    # Behavioral risks
    if behavioral_metadata.redirect_count and behavioral_metadata.redirect_count > 5:
        risks.append({
            "type": "behavioral_risk",
            "indicator": f"Excessive redirects: {behavioral_metadata.redirect_count}",
            "score": 40,
            "mitigation": "Analyze redirect chain for malicious patterns"
        })

    return risks
```

## Confidence Score Calculation

### Overall Confidence Formula
```python
def calculate_overall_confidence(consistency_scores):
    if not consistency_scores:
        return 0.5  # Neutral confidence

    # Weight different validation categories
    category_weights = {
        "network_topology": 0.3,
        "redirect_chain": 0.25,
        "technology_stack": 0.2,
        "behavioral_patterns": 0.25
    }

    # Score mapping
    score_values = {
        ConsistencyLevel.HIGH: 1.0,
        ConsistencyLevel.MEDIUM: 0.7,
        ConsistencyLevel.LOW: 0.4,
        ConsistencyLevel.INCONSISTENT: 0.1
    }

    weighted_score = 0
    total_weight = 0

    for category, consistency_level in consistency_scores.items():
        if category in category_weights:
            weight = category_weights[category]
            score = score_values.get(consistency_level, 0.5)
            weighted_score += weight * score
            total_weight += weight

    return weighted_score / total_weight if total_weight > 0 else 0.5
```

### Confidence Modifiers
```python
def apply_confidence_modifiers(base_confidence, modifiers):
    adjusted_confidence = base_confidence

    for modifier in modifiers:
        if modifier["type"] == "data_freshness":
            # Recent data is more reliable
            age_penalty = min(0.2, modifier["age_hours"] / 24 * 0.1)
            adjusted_confidence -= age_penalty

        elif modifier["type"] == "provider_count":
            # More providers increase confidence
            if modifier["count"] >= 3:
                adjusted_confidence += 0.1

        elif modifier["type"] == "anomaly_detected":
            # Anomalies reduce confidence
            adjusted_confidence -= 0.15

    return max(0.0, min(1.0, adjusted_confidence))
```

## Integration with Threat Assessment

### Threat Score Adjustment
```python
def adjust_threat_score_with_metadata(base_threat_score, metadata_analysis):
    adjusted_score = base_threat_score

    # Confidence-based adjustment
    confidence_factor = metadata_analysis.confidence_score
    if confidence_factor < 0.5:
        # Low confidence reduces certainty
        adjusted_score = base_threat_score * 0.8
    elif confidence_factor > 0.8:
        # High confidence increases certainty
        adjusted_score = min(100, base_threat_score * 1.2)

    # Anomaly-based adjustment
    anomaly_count = len(metadata_analysis.anomalies)
    if anomaly_count > 3:
        adjusted_score += 15  # Multiple anomalies increase risk

    # Risk indicator adjustment
    risk_count = len(metadata_analysis.risk_indicators)
    adjusted_score += risk_count * 5  # Each risk indicator adds 5 points

    return max(0, min(100, int(adjusted_score)))
```

### Synthesis Integration
```json
{
  "metadata_analysis": {
    "network_consistency": "high",
    "technology_confidence": 0.85,
    "infrastructure_diversity": {
      "unique_ips": 2,
      "unique_countries": 1,
      "unique_asns": 2,
      "unique_domains": 3
    },
    "technology_stack": {
      "servers_detected": 1,
      "frameworks_detected": 0,
      "cms_detected": 1
    },
    "behavioral_anomalies": [],
    "risk_indicators": ["High-risk ASN detected: AS13335"],
    "confidence_score": 0.75,
    "cross_validation_status": "high_consistency"
  }
}
```

## Best Practices

### Validation Strategy
- Always compare at least 2 data sources for each metadata category
- Weight consistency scores based on provider reliability
- Consider temporal factors (data freshness, analysis timing)
- Account for legitimate variations (CDN usage, load balancing)

### Error Handling
```python
def handle_validation_errors(validation_errors):
    for error in validation_errors:
        if error["type"] == "insufficient_data":
            # Use single-provider data with reduced confidence
            return create_low_confidence_result(error["available_data"])
        elif error["type"] == "provider_timeout":
            # Continue with available providers
            continue
        elif error["type"] == "data_corruption":
            # Exclude corrupted data from validation
            exclude_provider_data(error["provider"])
```

### Performance Optimization
- Cache validation results for repeated analyses
- Parallelize cross-validation calculations
- Use sampling for large datasets
- Implement early termination for clear consensus cases

This cross-validation framework ensures that threat assessments are based on corroborated intelligence rather than single-source data, significantly improving accuracy and reducing false positives.
