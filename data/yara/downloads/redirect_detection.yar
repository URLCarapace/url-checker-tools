/*
    Simplified Redirect Pattern Detection Rules
    Detect basic redirect behaviors in web content
*/

rule Basic_JavaScript_Redirects
{
    meta:
        description = "Detects basic JavaScript redirect patterns"
        author = "URL Checker Security Team"
        severity = "low"
        category = "redirect"

    strings:
        $js_redirect1 = "window.location.href" nocase
        $js_redirect2 = "window.location.replace" nocase
        $js_redirect3 = "document.location" nocase

    condition:
        any of them
}

rule Meta_Refresh_Redirects
{
    meta:
        description = "Detects meta refresh redirect tags"
        author = "URL Checker Security Team"
        severity = "medium"
        category = "redirect"

    strings:
        $meta_refresh = "<meta http-equiv=\"refresh\"" nocase
        $meta_redirect = "content=" nocase

    condition:
        $meta_refresh and $meta_redirect
}

rule URL_Shortener_Content
{
    meta:
        description = "Detects URL shortener service content"
        author = "URL Checker Security Team"
        severity = "medium"
        category = "redirect"

    strings:
        $shortener1 = "bit.ly" nocase
        $shortener2 = "tinyurl" nocase
        $shortener3 = "goo.gl" nocase
        $redirect_text = "redirecting" nocase

    condition:
        any of ($shortener*) and $redirect_text
}
