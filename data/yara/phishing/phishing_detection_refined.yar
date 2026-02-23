/*
 * Refined Phishing Detection Rules - Production Ready
 * Author: URL Checker Security Team
 * Updated: 2025-09-01
 * 
 * Features:
 * - Domain whitelist system to reduce false positives
 * - Context-aware authority impersonation detection
 * - Improved login form analysis with legitimacy checks
 * - Enhanced typosquatting detection
 */

rule Whitelist_Aware_Credential_Harvesting
{
    meta:
        description = "Detects credential harvesting forms excluding legitimate domains"
        author = "Security Team"
        severity = "high"
        category = "phishing"

    strings:
        // Major legitimate domains - these should NOT trigger
        $legit1 = /https?:\/\/[a-zA-Z0-9\-]*\.?(google|youtube|gmail)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch|dk|se|no|fi|pl)/i
        $legit2 = /https?:\/\/[a-zA-Z0-9\-]*\.?(microsoft|live|outlook|office365|hotmail)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch)/i
        $legit3 = /https?:\/\/[a-zA-Z0-9\-]*\.?(github|gitlab|bitbucket)\.(com|io|org)/i
        $legit4 = /https?:\/\/[a-zA-Z0-9\-]*\.?(paypal)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch)/i
        $legit5 = /https?:\/\/[a-zA-Z0-9\-]*\.?(amazon|aws)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch|dk|se|no|fi|pl)/i
        $legit6 = /https?:\/\/[a-zA-Z0-9\-]*\.?(apple|icloud)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch)/i
        $legit7 = /https?:\/\/[a-zA-Z0-9\-]*\.?(facebook|meta|instagram)\.(com|de)/i
        
        // European services
        $legit_eu1 = /https?:\/\/[a-zA-Z0-9\-]*\.?(ing|rabobank|abnamro)\.(com|nl|de)/i
        $legit_eu2 = /https?:\/\/[a-zA-Z0-9\-]*\.?(deutsche-bank|commerzbank)\.(com|de)/i
        $legit_eu3 = /https?:\/\/[a-zA-Z0-9\-]*\.?(bnpparibas|societegenerale)\.(com|fr)/i
        $legit_eu4 = /https?:\/\/[a-zA-Z0-9\-]*\.?(santander|bbva|caixabank)\.(com|es)/i
        
        // Government domains
        $legit_gov = /https?:\/\/[a-zA-Z0-9\-]*\.(gov|gouv|government|europa)\./i

        // Password input fields
        $password = /<input[^>]*(?:type|name|id)\s*=\s*["']password["']/i
        
        // Email/username fields
        $email = /<input[^>]*(?:type\s*=\s*["']email["']|name\s*=\s*["'](?:email|username|user)["'])/i

        // Suspicious form actions (external domains)
        $external_form = /<form[^>]*action\s*=\s*["']https?:\/\/[a-zA-Z0-9\-]*\.(?:tk|ml|ga|cf|xyz|click|top|work|date)[^"']*["']/i
        
        // Phishing urgency language combined with credential requests
        $urgent_cred = /(urgent|expire|suspend|immediate).*(?:verify|update|confirm).*(?:account|login|password)/i
        $threat_cred = /(unauthorized|suspicious|breach|compromised).*(?:verify|secure|update|login)/i

    condition:
        // Exclude all legitimate domains
        not any of ($legit*) and
        
        // Require credential fields AND suspicious context
        $password and $email and
        ($external_form or $urgent_cred or $threat_cred)
}

rule Context_Aware_Brand_Impersonation
{
    meta:
        description = "Detects brand impersonation with domain and context awareness"
        author = "Security Team"
        severity = "high"
        category = "phishing"

    strings:
        // Legitimate brand domains (same as above)
        $legit1 = /https?:\/\/[a-zA-Z0-9\-]*\.?(google|youtube|gmail)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch|dk|se|no|fi|pl)/i
        $legit2 = /https?:\/\/[a-zA-Z0-9\-]*\.?(microsoft|live|outlook|office365)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch)/i
        $legit3 = /https?:\/\/[a-zA-Z0-9\-]*\.?(paypal)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch)/i
        $legit4 = /https?:\/\/[a-zA-Z0-9\-]*\.?(amazon|aws)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch|dk|se|no|fi|pl)/i
        $legit5 = /https?:\/\/[a-zA-Z0-9\-]*\.?(apple|icloud)\.(com|de|co\.uk|fr|it|es|nl|be|at|ch)/i
        $legit6 = /https?:\/\/[a-zA-Z0-9\-]*\.?(facebook|meta|instagram)\.(com|de)/i
        $legit_banks = /https?:\/\/[a-zA-Z0-9\-]*\.?(ing|rabobank|deutsche-bank|bnpparibas|santander)\.(com|de|nl|fr|es)/i
        
        // Brand names with suspicious TLDs
        $fake_paypal = /https?:\/\/[a-zA-Z0-9\-]*paypal[a-zA-Z0-9\-]*\.(?:tk|ml|ga|cf|xyz|click|top|work|date|download|stream)/i
        $fake_amazon = /https?:\/\/[a-zA-Z0-9\-]*amazon[a-zA-Z0-9\-]*\.(?:tk|ml|ga|cf|xyz|click|top|work|date|download|stream)/i
        $fake_microsoft = /https?:\/\/[a-zA-Z0-9\-]*microsoft[a-zA-Z0-9\-]*\.(?:tk|ml|ga|cf|xyz|click|top|work|date|download|stream)/i
        $fake_google = /https?:\/\/[a-zA-Z0-9\-]*google[a-zA-Z0-9\-]*\.(?:tk|ml|ga|cf|xyz|click|top|work|date|download|stream)/i
        
        // Typosquatting patterns
        $typo_paypal = /payp[ai]l|p[ai]ypal|payp[ao]l|paipal|paypaI|paypa1/i
        $typo_amazon = /am[ai]zon|amaz[o0]n|amazom|amazone|amaz0n/i
        $typo_google = /g[o0]ogle|go[o0]gle|googIe|goog1e|gooogle/i
        $typo_microsoft = /m[i1]crosoft|microsooft|microsft|microsft/i
        
        // Brand + urgency + credential request
        $brand_urgent1 = /(paypal|amazon|microsoft|google|apple).*(?:urgent|expire|suspend).*(?:verify|login|update)/i
        $brand_urgent2 = /(account.*suspended|unauthorized.*access).*(?:paypal|amazon|microsoft|google|apple)/i

    condition:
        not any of ($legit*) and
        (any of ($fake_*) or any of ($typo_*) or any of ($brand_urgent*))
}

rule European_Authority_Impersonation
{
    meta:
        description = "Detects European authority impersonation with proper context"
        author = "Security Team"
        severity = "high"
        category = "phishing"

    strings:
        // Legitimate government domains
        $legit_gov_eu = /https?:\/\/[a-zA-Z0-9\-]*\.(gov|gouv|government|europa)\.(de|nl|fr|it|es|be|at|ch|dk|se|no|fi|pl|cz|sk|hu|ro|bg|hr|si|ee|lv|lt|eu)/i
        $legit_gov_us = /https?:\/\/[a-zA-Z0-9\-]*\.gov/i
        
        // Authority + threat + action (not just acronym)  
        $interpol_scam = /interpol.*(?:investigation|warrant|arrest|criminal|freeze|account|payment).*(?:verify|pay|transfer|confirm)/i
        $europol_scam = /europol.*(?:investigation|warrant|criminal|money.*laundering).*(?:verify|pay|confirm|cooperate)/i
        $fbi_scam = /fbi.*(?:investigation|warrant|arrest|criminal|cyber.*crime|money.*laundering).*(?:verify|pay|fine|penalty|avoid.*arrest)/i
        $cia_scam = /cia.*(?:classified|security.*clearance|investigation).*(?:verify|update|confirm)/i
        
        // Broader authority patterns
        $authority_fine = /(?:fbi|cia|interpol|europol|police|government).*(?:fine|penalty|arrest|investigation).*(?:pay|avoid|resolve)/i
        
        // Tax scams with context (less relevant in EU but possible)
        $tax_context = /(?:tax.*(?:refund|rebate|audit|owe|penalty)|internal.*revenue).*(?:claim|verify|pay|update|confirm)/i
        
        // Generic government threat + action
        $gov_threat = /(?:government|federal|national).*(?:agency|department|investigation).*(?:freeze|suspend|investigate).*(?:account|verify|pay)/i
        $police_threat = /(?:police|law.*enforcement).*(?:investigation|warrant|fine|penalty).*(?:pay|verify|confirm|resolve)/i
        
        // Urgency with authority context
        $urgent_authority = /(?:immediate|urgent|within.*hours).*(?:response|action|payment).*(?:required|mandatory|necessary)/i

    condition:
        not any of ($legit_gov*) and
        (any of ($interpol_scam, $europol_scam, $fbi_scam, $cia_scam, $tax_context, $gov_threat, $police_threat, $authority_fine) and
         $urgent_authority)
}

rule Suspicious_URL_Indicators
{
    meta:
        description = "Detects suspicious URL patterns and domain characteristics"
        author = "Security Team"
        severity = "medium"
        category = "phishing"

    strings:
        // High-risk TLDs with brand keywords
        $suspicious_tld = /https?:\/\/[a-zA-Z0-9\-]*(?:bank|secure|login|verify|account|pay)[a-zA-Z0-9\-]*\.(?:tk|ml|ga|cf|xyz|click|top|work|date|download|stream|zip)/i
        
        // URL shorteners with login context
        $shortener_login = /(?:bit\.ly|tinyurl\.com|t\.co|short\.link|goo\.gl).*(?:login|verify|secure|account|update)/i
        
        // Suspicious subdomain patterns
        $suspicious_subdomain = /https?:\/\/(?:secure|login|verify|account|update|auth|signin)[a-zA-Z0-9\-]*\.[a-zA-Z0-9\-]*\.(?:tk|ml|ga|cf|xyz)/i
        
        // Long suspicious domains (common in phishing)
        $long_suspicious = /https?:\/\/[a-zA-Z0-9\-]{25,}\.(?:tk|ml|ga|cf|xyz|click|top)/i

    condition:
        any of them
}