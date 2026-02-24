rule Contextual_Phishing_Indicators
{
    meta:
        description = "Context-aware phishing detection to reduce false positives"
        author = "Security Team"
        date = "2025-09-01"
        severity = "low"

    strings:
        // Legitimate domains whitelist
        $whitelist_major = /https?:\/\/[a-zA-Z0-9\-]*\.?(google|microsoft|github|stackoverflow|mozilla|w3|apache|oracle|ibm|redhat|canonical|debian|ubuntu|fedora|centos)\.(?:com|org|net|io|de|co\.uk|fr)/i
        $whitelist_social = /https?:\/\/[a-zA-Z0-9\-]*\.?(facebook|twitter|linkedin|instagram|youtube|reddit|discord|slack|zoom|teams)\.(?:com|org|de)/i
        $whitelist_dev = /https?:\/\/[a-zA-Z0-9\-]*\.?(npm|pypi|docker|gitlab|bitbucket|sourceforge|packagist|crates|nuget)\.(?:com|org|io)/i
        $whitelist_cloud = /https?:\/\/[a-zA-Z0-9\-]*\.?(aws|azure|gcp|cloudflare|heroku|digitalocean|linode)\.(?:com|net|io)/i

        // Suspicious combinations that suggest phishing
        $phish_combo1 = /(urgent|expire|suspend).*(?:account|login|verify).*(?:click|update|confirm)/i
        $phish_combo2 = /(security|unauthorized).*(?:alert|access|breach).*(?:verify|login|secure)/i
        $phish_combo3 = /(winner|congratulations|prize).*(?:claim|verify|confirm).*(?:account|details)/i

        // External form submissions to suspicious domains
        $external_form = /<form[^>]*action\s*=\s*["']https?:\/\/[^"']*\.(?:tk|ml|ga|cf|xyz|click|top|work|date|download|stream)\/[^"']*["']/i
        $external_form_suspicious = /<form[^>]*action\s*=\s*["']https?:\/\/[a-zA-Z0-9\-]*(?:secure|login|verify|account)[a-zA-Z0-9\-]*\.[^"']*["']/i

        // Multiple credential requests
        $multi_cred = /(?:password|email|username).*(?:password|email|username).*(?:submit|login|verify)/i

    condition:
        // Exclude whitelisted domains
        not any of ($whitelist_*) and

        // Require suspicious combinations, not just presence of login terms
        (any of ($phish_combo*) or $external_form or $external_form_suspicious or $multi_cred)
}
