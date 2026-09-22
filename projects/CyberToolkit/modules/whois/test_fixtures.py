VERISIGN_STYLE = """Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar-corp.example
Registrar URL: http://www.registrar-corp.example
Updated Date: 2024-08-14T04:39:36Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2025-08-13T04:00:00Z
Registrar: Registrar Corp Inc.
Registrar IANA ID: 1234
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation
"""

RIPE_STYLE = """domain:       example.de
nserver:      ns1.example-hosting.de
nserver:      ns2.example-hosting.de
status:       connect
changed:      2023-11-02T10:15:00Z
source:       DENIC
"""

JPRS_STYLE = """[Domain Name]                  EXAMPLE.JP

[Registrant]                   Example Corp

[Name Server]                  ns1.example.jp
[Name Server]                  ns2.example.jp
[Status]                       Active
[Created on]                   2001-04-01
[Last Updated]                 2024-04-01
"""

NOT_FOUND_STYLE = """No match for domain "NOTAREALDOMAIN123456.COM"

>>> Last update of whois database: 2024-08-14T10:00:00Z <<<
"""

NOT_FOUND_STYLE_2 = """NOT FOUND
"""

AVAILABLE_STYLE = """Domain Name: SOMEAVAILABLEDOMAIN.COM
Status: AVAILABLE
"""

EMPTY_RESPONSE = ""

MALFORMED_RESPONSE = """asdkjasjd 1231 !!!! random garbage
no colons or structure here at all
%%%% just noise %%%%
"""

REDACTED_PRIVACY_STYLE = """Domain Name: PRIVATEDOMAIN.COM
Registrar: Privacy Registrar LLC
Creation Date: 2020-01-15T00:00:00Z
Registry Expiry Date: 2026-01-15T00:00:00Z
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: REDACTED FOR PRIVACY
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: NS1.PRIVACYDNS.COM
Name Server: NS2.PRIVACYDNS.COM
"""