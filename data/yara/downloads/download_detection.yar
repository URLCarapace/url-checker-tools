/*
 * File Download Detection Rules
 * Author: URL Checker Security Team
 * Updated: 2025-01-21
 */

rule Executable_Download_Links
{
    meta:
        description = "Detects links to executable file downloads"
        author = "Security Team"
        severity = "high"
        category = "download"

    strings:
        // Direct executable links - standard HTML (quoted)
        $exe1 = /<a[^>]*href\s*=\s*["'][^"']*\.exe["']/i
        $exe2 = /<a[^>]*href\s*=\s*["'][^"']*\.msi["']/i
        $exe3 = /<a[^>]*href\s*=\s*["'][^"']*\.scr["']/i
        $exe4 = /<a[^>]*href\s*=\s*["'][^"']*\.com["']/i
        $exe5 = /<a[^>]*href\s*=\s*["'][^"']*\.bat["']/i
        $exe6 = /<a[^>]*href\s*=\s*["'][^"']*\.cmd["']/i
        $exe7 = /<a[^>]*href\s*=\s*["'][^"']*\.pif["']/i

        // Direct executable links - unquoted href attributes
        $exe1_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.exe[\s>]/i
        $exe2_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.msi[\s>]/i
        $exe3_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.scr[\s>]/i
        $exe4_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.com[\s>]/i
        $exe5_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.bat[\s>]/i
        $exe6_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.cmd[\s>]/i
        $exe7_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.pif[\s>]/i

        // Direct executable links - HTML-encoded
        $exe1_enc = /href\s*=\s*["'][^"']*\.exe["'][^&]*&gt;/i
        $exe2_enc = /href\s*=\s*["'][^"']*\.msi["'][^&]*&gt;/i
        $exe3_enc = /href\s*=\s*["'][^"']*\.scr["'][^&]*&gt;/i
        $exe4_enc = /href\s*=\s*["'][^"']*\.com["'][^&]*&gt;/i
        $exe5_enc = /href\s*=\s*["'][^"']*\.bat["'][^&]*&gt;/i
        $exe6_enc = /href\s*=\s*["'][^"']*\.cmd["'][^&]*&gt;/i
        $exe7_enc = /href\s*=\s*["'][^"']*\.pif["'][^&]*&gt;/i

        // Script downloads - standard HTML (quoted)
        $script1 = /<a[^>]*href\s*=\s*["'][^"']*\.vbs["']/i
        $script2 = /<a[^>]*href\s*=\s*["'][^"']*\.js["']/i
        $script3 = /<a[^>]*href\s*=\s*["'][^"']*\.jar["']/i
        $script4 = /<a[^>]*href\s*=\s*["'][^"']*\.ps1["']/i

        // Script downloads - unquoted href attributes
        $script1_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.vbs[\s>]/i
        $script2_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.js[\s>]/i
        $script3_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.jar[\s>]/i
        $script4_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.ps1[\s>]/i

        // Script downloads - HTML-encoded
        $script1_enc = /href\s*=\s*["'][^"']*\.vbs["'][^&]*&gt;/i
        $script2_enc = /href\s*=\s*["'][^"']*\.js["'][^&]*&gt;/i
        $script3_enc = /href\s*=\s*["'][^"']*\.jar["'][^&]*&gt;/i
        $script4_enc = /href\s*=\s*["'][^"']*\.ps1["'][^&]*&gt;/i

        // Document with macros - standard HTML (quoted)
        $macro1 = /<a[^>]*href\s*=\s*["'][^"']*\.docm["']/i
        $macro2 = /<a[^>]*href\s*=\s*["'][^"']*\.xlsm["']/i
        $macro3 = /<a[^>]*href\s*=\s*["'][^"']*\.pptm["']/i

        // Document with macros - unquoted href attributes
        $macro1_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.docm[\s>]/i
        $macro2_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.xlsm[\s>]/i
        $macro3_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.pptm[\s>]/i

        // Document with macros - HTML-encoded
        $macro1_enc = /href\s*=\s*["'][^"']*\.docm["'][^&]*&gt;/i
        $macro2_enc = /href\s*=\s*["'][^"']*\.xlsm["'][^&]*&gt;/i
        $macro3_enc = /href\s*=\s*["'][^"']*\.pptm["'][^&]*&gt;/i

    condition:
        any of them
}

rule Archive_Download_Links
{
    meta:
        description = "Detects links to archive downloads (potential malware containers)"
        author = "Security Team"
        severity = "medium"
        category = "download"

    strings:
        // Archive formats - standard HTML (quoted)
        $zip = /<a[^>]*href\s*=\s*["'][^"']*\.zip["']/i
        $rar = /<a[^>]*href\s*=\s*["'][^"']*\.rar["']/i
        $tar = /<a[^>]*href\s*=\s*["'][^"']*\.tar["']/i
        $gz = /<a[^>]*href\s*=\s*["'][^"']*\.(tar\.gz|tgz)["']/i
        $seven_zip = /<a[^>]*href\s*=\s*["'][^"']*\.7z["']/i
        $iso = /<a[^>]*href\s*=\s*["'][^"']*\.iso["']/i

        // Archive formats - unquoted href attributes
        $zip_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.zip[\s>]/i
        $rar_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.rar[\s>]/i
        $tar_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.tar[\s>]/i
        $gz_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.(tar\.gz|tgz)[\s>]/i
        $seven_zip_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.7z[\s>]/i
        $iso_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.iso[\s>]/i

        // Archive formats - HTML-encoded (for pages with encoded content)
        $zip_enc = /href\s*=\s*["'][^"']*\.zip["'][^&]*&gt;/i
        $rar_enc = /href\s*=\s*["'][^"']*\.rar["'][^&]*&gt;/i
        $tar_enc = /href\s*=\s*["'][^"']*\.tar["'][^&]*&gt;/i
        $gz_enc = /href\s*=\s*["'][^"']*\.(tar\.gz|tgz)["'][^&]*&gt;/i
        $seven_zip_enc = /href\s*=\s*["'][^"']*\.7z["'][^&]*&gt;/i
        $iso_enc = /href\s*=\s*["'][^"']*\.iso["'][^&]*&gt;/i

        // Suspicious download text
        $download_text1 = /<a[^>]*>(download|click here|get file)/i
        $download_text2 = /href\s*=\s*["'][^"']*\.(zip|rar|7z|iso)["'][^>]*>(download|file)/i

    condition:
        any of them
}

rule Document_Download_Links
{
    meta:
        description = "Detects links to document downloads (presentations, PDFs, spreadsheets)"
        author = "Security Team"
        severity = "low"
        category = "download"

    strings:
        // Office documents - standard HTML (quoted)
        $pdf = /<a[^>]*href\s*=\s*["'][^"']*\.pdf["']/i
        $docx = /<a[^>]*href\s*=\s*["'][^"']*\.docx["']/i
        $xlsx = /<a[^>]*href\s*=\s*["'][^"']*\.xlsx["']/i
        $pptx = /<a[^>]*href\s*=\s*["'][^"']*\.pptx["']/i
        $txt = /<a[^>]*href\s*=\s*["'][^"']*\.txt["']/i

        // Office documents - unquoted href attributes
        $pdf_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.pdf[\s>]/i
        $docx_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.docx[\s>]/i
        $xlsx_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.xlsx[\s>]/i
        $pptx_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.pptx[\s>]/i
        $txt_unq = /<a[^>]*href\s*=\s*[^"'\s>]*\.txt[\s>]/i

        // Office documents - HTML-encoded (for pages with encoded content)
        $pdf_enc = /href\s*=\s*["'][^"']*\.pdf["'][^&]*&gt;/i
        $docx_enc = /href\s*=\s*["'][^"']*\.docx["'][^&]*&gt;/i
        $xlsx_enc = /href\s*=\s*["'][^"']*\.xlsx["'][^&]*&gt;/i
        $pptx_enc = /href\s*=\s*["'][^"']*\.pptx["'][^&]*&gt;/i
        $txt_enc = /href\s*=\s*["'][^"']*\.txt["'][^&]*&gt;/i

        // Media files
        $mp4_enc = /href\s*=\s*["'][^"']*\.mp4["'][^&]*&gt;/i
        $mp3_enc = /href\s*=\s*["'][^"']*\.mp3["'][^&]*&gt;/i

    condition:
        any of them
}

rule Suspicious_File_Hosting
{
    meta:
        description = "Detects links to suspicious file hosting services"
        author = "Security Team"
        severity = "medium"
        category = "download"

    strings:
        // Free file hosting (often used for malware)
        $hosting1 = /<a[^>]*href\s*=\s*["'][^"']*mediafire\.com/i
        $hosting2 = /<a[^>]*href\s*=\s*["'][^"']*mega\.nz/i
        $hosting3 = /<a[^>]*href\s*=\s*["'][^"']*4shared\.com/i
        $hosting4 = /<a[^>]*href\s*=\s*["'][^"']*sendspace\.com/i
        $hosting5 = /<a[^>]*href\s*=\s*["'][^"']*rapidshare/i
        $hosting6 = /<a[^>]*href\s*=\s*["'][^"']*filejoker\.net/i
        $hosting7 = /<a[^>]*href\s*=\s*["'][^"']*zippyshare\.com/i

        // Temporary file hosting
        $temp1 = /<a[^>]*href\s*=\s*["'][^"']*wetransfer\.com/i
        $temp2 = /<a[^>]*href\s*=\s*["'][^"']*filedropper\.com/i
        $temp3 = /<a[^>]*href\s*=\s*["'][^"']*filebin\.net/i

        // Anonymous/paste sites
        $paste1 = /<a[^>]*href\s*=\s*["'][^"']*pastebin\.com/i
        $paste2 = /<a[^>]*href\s*=\s*["'][^"']*hastebin\.com/i

    condition:
        any of them
}

rule Direct_Download_Triggers
{
    meta:
        description = "Detects automatic download triggers"
        author = "Security Team"
        severity = "high"
        category = "download"

    strings:
        // Auto-download meta tags
        $auto1 = /<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*url\s*=[^>]*\.(exe|zip|rar)/i

        // JavaScript auto-download
        $js_download1 = /window\.location\s*=\s*["'][^"']*\.(exe|zip|rar|msi)["']/i
        $js_download2 = /location\.href\s*=\s*["'][^"']*\.(exe|zip|rar|msi)["']/i
        $js_download3 = /window\.open\s*\(\s*["'][^"']*\.(exe|zip|rar|msi)["']/i

        // HTML5 download attribute
        $html5_download = /<a[^>]*download[^>]*href\s*=\s*["'][^"']*\.(exe|zip|rar|msi)/i

        // Form auto-submit to download
        $form_download = /<form[^>]*action\s*=\s*["'][^"']*\.(exe|zip|rar|msi)["'][^>]*>/i

    condition:
        any of them
}

rule Disguised_Download_Links
{
    meta:
        description = "Detects disguised or deceptive download links"
        author = "Security Team"
        severity = "high"
        category = "download"

    strings:
        // Disguised as legitimate software
        $disguise1 = /<a[^>]*href\s*=\s*["'][^"']*\.(exe|zip)["'][^>]*>(adobe|flash|java|chrome|firefox)/i
        $disguise2 = /<a[^>]*href\s*=\s*["'][^"']*\.(exe|zip)["'][^>]*>(update|install|download)/i
        $disguise3 = /<a[^>]*href\s*=\s*["'][^"']*\.(exe|zip)["'][^>]*>(security|antivirus|cleanup)/i

        // Fake codec/player downloads
        $codec1 = /<a[^>]*href\s*=\s*["'][^"']*\.(exe|zip)["'][^>]*>(codec|player|plugin)/i

        // Suspicious button styling to look like legitimate downloads
        $button1 = /<button[^>]*onclick[^>]*location[^>]*\.(exe|zip|rar)/i
        $button2 = /<div[^>]*onclick[^>]*window\.open[^>]*\.(exe|zip|rar)/i

    condition:
        any of them
}
