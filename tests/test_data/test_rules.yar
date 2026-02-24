rule DetectXSS {
    meta:
        description = "Detects XSS patterns in web content"
        author = "URL Checker Test Suite"

    strings:
        $xss1 = "<script>alert("
        $xss2 = "onerror=\"alert("
        $xss3 = "javascript:alert("
        $xss4 = "onload=\"alert("
        $xss5 = "document.cookie"
        $xss6 = "eval(atob("

    condition:
        any of ($xss*)
}

rule DetectPhishing {
    meta:
        description = "Detects phishing patterns"
        author = "URL Checker Test Suite"

    strings:
        $phish1 = "username" nocase
        $phish2 = "password" nocase
        $phish3 = "Social Security" nocase
        $phish4 = "account will be suspended" nocase
        $phish5 = "verify immediately" nocase
        $phish6 = "suspicious-site.com"

    condition:
        3 of ($phish*)
}

rule DetectMalwareDownload {
    meta:
        description = "Detects malware download patterns"
        author = "URL Checker Test Suite"

    strings:
        $mal1 = ".exe"
        $mal2 = ".scr"
        $mal3 = ".bat"
        $mal4 = "flash_update"
        $mal5 = "security_patch"
        $mal6 = "window.open("
        $mal7 = "exploit.html"

    condition:
        any of ($mal*)
}

rule DetectSuspiciousBase64 {
    meta:
        description = "Detects suspicious base64 encoded content"
        author = "URL Checker Test Suite"

    strings:
        $b64_1 = "atob("
        $b64_2 = "YWxlcnQ" // alert in base64
        $b64_3 = "ZXZhbA" // eval in base64

    condition:
        any of ($b64*)
}
