rule HTTP_Download_Headers
{
    meta:
        description = "Detects HTTP headers indicating file downloads"
        author = "Security Team"
        severity = "medium"
        category = "download"

    strings:
        // These would be detected in metadata, not content
        // This rule is for completeness but may not trigger in current implementation
        $header1 = /content-disposition.*attachment/i
        $header2 = /content-type.*application\/octet-stream/i
        $header3 = /content-type.*application\/x-msdownload/i

    condition:
        any of them
}
