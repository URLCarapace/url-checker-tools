rule DNS_Content_Block_Detection
{
    meta:
        description = "Detects DNS/content filtering block pages from various providers"
        author = "Security Team"
        date = "2025-09-09"
        severity = "high"
        category = "blocked"
        confidence = "high"

    strings:
        // Whitelist patterns for legitimate sites that might contain blocking-like text
        $youtube_legit = "youtube.com"
        $google_legit = "google.com"
        $facebook_legit = "facebook.com"
        $twitter_legit = "twitter.com"
        $instagram_legit = "instagram.com"
        $tiktok_legit = "tiktok.com"
        $linkedin_legit = "linkedin.com"
        $reddit_legit = "reddit.com"
        $github_legit = "github.com"
        $stackoverflow_legit = "stackoverflow.com"
        // OpenDNS/Umbrella block pages
        $opendns_title = "<title>OpenDNS</title>"
        $opendns_block = "This domain is blocked"
        $opendns_category = "categorized and blocked"
        $umbrella_title = "<title>Cisco Umbrella</title>"
        $umbrella_block = "blocked by your organization"

        // Cloudflare block pages
        $cloudflare_title = "<title>Access denied</title>"
        $cloudflare_block = "Access denied | www.cloudflare.com used Cloudflare to restrict access"
        $cloudflare_ray = "Ray ID:" nocase
        $cloudflare_error = "cloudflare" nocase
        $cloudflare_1020 = "Error 1020"
        $cloudflare_1025 = "Error 1025"

        // Generic corporate/enterprise filtering
        $corporate_blocked = /blocked.*(?:policy|administrator|organization|company)/i
        $access_denied = /access.*(?:denied|restricted|blocked).*(?:policy|filter|security)/i
        $content_filter = /content.*(?:filter|blocked|restricted).*(?:category|policy)/i
        $web_filter = /web.*(?:filter|blocking|restriction).*(?:enabled|active)/i

        // Fortinet FortiGate
        $fortinet_title = "<title>FortiGate"
        $fortinet_block = "FortiGuard Web Filtering"
        $fortinet_category = "Category: "

        // Sophos UTM/XG
        $sophos_title = "<title>Sophos"
        $sophos_block = "blocked by Sophos"
        $sophos_category = "Web Protection"

        // Palo Alto Networks
        $paloalto_title = "<title>Access Blocked"
        $paloalto_block = "URL filtering"
        $paloalto_category = "blocked by policy"

        // Barracuda
        $barracuda_title = "<title>Barracuda"
        $barracuda_block = "Web Filter Block"
        $barracuda_category = "Category blocked"

        // Blue Coat/Symantec ProxySG
        $bluecoat_title = "<title>Access Denied"
        $bluecoat_block = "ProxySG"
        $bluecoat_category = "This request was blocked"

        // Websense/Forcepoint
        $websense_title = "<title>Websense"
        $websense_block = "blocked by filtering policy"
        $forcepoint_title = "<title>Forcepoint"
        $forcepoint_block = "Content blocked"

        // ISP-level blocking (generic patterns)
        $isp_block1 = /blocked.*(?:isp|internet service provider|network administrator)/i
        $isp_block2 = /site.*(?:unavailable|blocked).*(?:request|administrator)/i

        // Generic block page indicators
        $generic_block1 = /<title>.*(?:blocked|denied|restricted).*<\/title>/i
        $generic_block2 = /<h1>.*(?:access denied|blocked|restricted).*<\/h1>/i
        $generic_block3 = /this (?:site|website|page|domain) (?:has been|is) blocked/i
        $generic_block4 = /access to this (?:site|website|page) (?:has been|is) (?:denied|blocked|restricted)/i

        // HTTPS certificate errors that might indicate blocking
        $cert_error = /certificate.*(?:invalid|untrusted|expired).*security/i
        $ssl_error = /ssl.*(?:error|connection.*failed)/i

        // Redirect loops or unusual redirects (potential blocking)
        $redirect_loop = /too many redirects/i
        $redirect_blocked = /redirect.*blocked/i

    condition:
        // Exclude legitimate sites that might contain blocking-like patterns in their content
        not any of ($*_legit) and (
            // Require specific vendor block page indicators or multiple generic indicators
            // to reduce false positives on legitimate sites like YouTube
            (
                // Specific vendor block pages (high confidence)
                any of ($opendns*, $umbrella*, $cloudflare*, $fortinet*, $sophos*, 
                       $paloalto*, $barracuda*, $bluecoat*, $websense*, $forcepoint*)
            ) or (
                // Corporate/ISP blocking patterns (medium confidence)
                any of ($corporate_blocked, $access_denied, $content_filter, $web_filter, $isp_block*)
            ) or (
                // Generic patterns only if combined with other indicators (lower false positive rate)
                any of ($generic_block*) and (
                    // Must be accompanied by additional blocking indicators
                    any of ($cert_error, $ssl_error, $redirect_loop, $redirect_blocked) or
                    // Or contain multiple generic blocking terms
                    #generic_block1 > 1 or #generic_block2 > 1 or #generic_block3 > 1 or #generic_block4 > 1
                )
            )
        )
}

rule Known_Blocker_URLs
{
    meta:
        description = "Detects redirects to known blocking/filtering service URLs"
        author = "Security Team"
        date = "2025-09-09"
        severity = "high"
        category = "blocked"
        threat_type = "blocked_by_dns_filter"
        confidence = "high"

    strings:
        // Corporate/Enterprise Filtering Services
        $fortinet_1 = "blocked.fortinet.com"
        $fortinet_2 = "fortigate.blocked"
        $fortinet_3 = "fortiguard.blocked"
        
        $sophos_1 = "blocked.sophos.com"
        $sophos_2 = "sophos.block"
        $sophos_3 = "utm.sophos.com/blocked"
        
        $paloalto_1 = "blocked.paloaltonetworks.com"
        $paloalto_2 = "pa-block.net"
        
        $barracuda_1 = "blocked.barracuda.com"
        $barracuda_2 = "barracuda.block"
        
        $bluecoat_1 = "access-denied.symantec.com"
        $bluecoat_2 = "blocked.bluecoat.com"
        $bluecoat_3 = "proxysecurity.symantec.com"
        
        $websense_1 = "blocked.websense.com"
        $websense_2 = "forcepoint.block"
        $websense_3 = "triton.websense.com"
        
        // Cloud/DNS Filtering Services
        $opendns_1 = "block.opendns.com"
        $opendns_2 = "blocked.opendns.com"
        $opendns_3 = "block-page.opendns.com"
        
        $umbrella_1 = "block.umbrella.com"
        $umbrella_2 = "blocked.umbrella.cisco.com"
        $umbrella_3 = "s-platform.api.opendns.com"
        
        $cloudflare_1 = "1.1.1.1/blocked"
        $cloudflare_2 = "cloudflare-dns.com/blocked"
        $cloudflare_3 = "teams.cloudflare.com/blocked"
        
        $quad9_1 = "blocked.quad9.net"
        $quad9_2 = "block-page.quad9.net"
        
        // Educational/Research Network Blocks
        $restena_1 = "blocking-page.restena.lu"
        $restena_2 = "blocked.restena.lu"
        $restena_3 = "filter.restena.lu"
        
        $janet_1 = "blocked.ja.net"
        $janet_2 = "content-block.ja.net"
        
        $geant_1 = "blocked.geant.org"
        $geant_2 = "filter.geant.org"
        
        // ISP-Level Blocking
        $bt_1 = "blocked.bt.com"
        $bt_2 = "cleanfeed.bt.com"
        
        $virgin_1 = "blocked.virginmedia.com"
        $virgin_2 = "webfilter.virginmedia.com"
        
        $sky_1 = "blocked.sky.com"
        $sky_2 = "shield.sky.com"
        
        $comcast_1 = "blocked.comcast.net"
        $comcast_2 = "security.xfinity.com/blocked"
        
        // Government/Regulatory Blocks
        $blocked_gov = "blocked.gov"
        $content_block = "contentblock.gov"
        
        // Generic Corporate Blocks
        $generic_1 = "blocked.company.com"
        $generic_2 = "webfilter.local"
        $generic_3 = "proxy-block.local"
        $generic_4 = "access-denied.local"
        $generic_5 = "content-filter.local"
        
        // Specific Known Blockers
        $k9web = "k9webprotection.com"
        $netnanny = "blocked.netnanny.com"
        $cybersitter = "blocked.cybersitter.com"
        $mcafee_web = "blocked.mcafee.com"
        $norton_web = "blocked.norton.com"
        $kaspersky_web = "blocked.kaspersky.com"
        
        // Academic/Library Filters
        $lightspeed_1 = "blocked.lightspeedsystems.com"
        $lightspeed_2 = "relay.lightspeedsystems.com"
        $goguardian = "blocked.goguardian.com"
        $securly = "blocked.securly.com"
        
        // DNS Security Services
        $cleanbrowsing = "blocked.cleanbrowsing.org"
        $yandex_dns = "blocked.yandex.com"
        $adguard_dns = "blocked.adguard.com"
        
        // Mobile/Carrier Filtering
        $tmobile_block = "blocked.t-mobile.com"
        $verizon_block = "blocked.verizon.net"
        $att_block = "blocked.att.net"

    condition:
        any of them
}

rule Malicious_Block_Page_Classification
{
    meta:
        description = "Classifies detected block pages as malicious threats"
        author = "Security Team"
        date = "2025-09-09"
        severity = "high" 
        category = "malicious"
        threat_type = "blocked_by_dns_filter"
        confidence = "high"

    condition:
        DNS_Content_Block_Detection or Known_Blocker_URLs
}