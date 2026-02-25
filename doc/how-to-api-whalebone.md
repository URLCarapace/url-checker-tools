UILISER que pour interroger 'https://api.cloud.joindns4.eu/whalebone/2/domain/analysis'

Exemple de requete:
curl -v -X 'GET' \
  'https://api.cloud.joindns4.eu/whalebone/2/domain/analysis?fqdn=sex.com' \
  -H 'accept: application/json' \
  -H 'Wb-Access-Key: [REDACTED]' \
  -H 'Wb-Secret-Key: [REDACTED]' | jq .

Exemple de réponse:
Note: Unnecessary use of -X or --request, GET is already inferred.
* Uses proxy env variable no_proxy == '*'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Host api.cloud.joindns4.eu:443 was resolved.
* IPv6: (none)
* IPv4: 195.154.196.163
*   Trying 195.154.196.163:443...
* Connected to api.cloud.joindns4.eu (195.154.196.163) port 443
* ALPN: curl offers h2,http/1.1
* (304) (OUT), TLS handshake, Client hello (1):
} [326 bytes data]
*  CAfile: /etc/ssl/cert.pem
*  CApath: none
* (304) (IN), TLS handshake, Server hello (2):
{ [122 bytes data]
* (304) (IN), TLS handshake, Unknown (8):
{ [19 bytes data]
* (304) (IN), TLS handshake, Certificate (11):
{ [2598 bytes data]
* (304) (IN), TLS handshake, CERT verify (15):
{ [264 bytes data]
* (304) (IN), TLS handshake, Finished (20):
{ [52 bytes data]
* (304) (OUT), TLS handshake, Finished (20):
} [52 bytes data]
* SSL connection using TLSv1.3 / AEAD-AES256-GCM-SHA384 / [blank] / UNDEF
* ALPN: server accepted h2
* Server certificate:
*  subject: CN=api.cloud.joindns4.eu
*  start date: Sep  3 12:10:07 2025 GMT
*  expire date: Dec  2 12:10:06 2025 GMT
*  subjectAltName: host "api.cloud.joindns4.eu" matched cert's "api.cloud.joindns4.eu"
*  issuer: C=US; O=Let's Encrypt; CN=R12
*  SSL certificate verify ok.
* using HTTP/2
* [HTTP/2] [1] OPENED stream for https://api.cloud.joindns4.eu/whalebone/2/domain/analysis?fqdn=sex.com
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: https]
* [HTTP/2] [1] [:authority: api.cloud.joindns4.eu]
* [HTTP/2] [1] [:path: /whalebone/2/domain/analysis?fqdn=sex.com]
* [HTTP/2] [1] [user-agent: curl/8.7.1]
* [HTTP/2] [1] [accept: application/json]
* [HTTP/2] [1] [wb-access-key: [REDACTED]]
* [HTTP/2] [1] [wb-secret-key: [REDACTED]]
> GET /whalebone/2/domain/analysis?fqdn=sex.com HTTP/2
> Host: api.cloud.joindns4.eu
> User-Agent: curl/8.7.1
> accept: application/json
> Wb-Access-Key: [REDACTED]
> Wb-Secret-Key: [REDACTED]
>
* Request completely sent off
< HTTP/2 200
< date: Tue, 09 Sep 2025 12:14:44 GMT
< content-type: application/json
< x-ratelimit-limit: 100
< x-ratelimit-remaining: 98
< x-ratelimit-reset: 1757420121
< x-request-id: 04ba8ab993d511dc08c9f519b2d99733
< strict-transport-security: max-age=31536000; includeSubDomains
<
{ [44 bytes data]
100    44    0    44    0     0    332      0 --:--:-- --:--:-- --:--:--   330
* Connection #0 to host api.cloud.joindns4.eu left intact

Exemple de retour JSON:
{
  "threats": [],
  "content_categories": [
    "porn"
  ]
}
