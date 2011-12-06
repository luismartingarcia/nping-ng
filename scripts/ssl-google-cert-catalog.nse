description = [[
Queries Google's Certificate Catalog for the SSL certificates retrieved from
target hosts.

The Certificate Catalog provides information about how recently and for how long
Google has seen the given certificate.  If a certificate doesn't appear in the
database, despite being correctly signed by a well-known CA and having a
matching domain name, it may be suspicious.  This script requires the
<code>ssl-cert</code> script to be run.
]]

---
-- @usage
-- nmap -p 443 --script ssl-cert,ssl-google-cert-catalog <host>
--
-- @output
-- PORT     STATE SERVICE
---443/tcp open  https
---| ssl-google-cert-catalog: 
---|   First/last date seen: 19 Aug 2011 / 10 Sep 2011
---|_  Days in between: 20

author = "Vasiliy Kulikov"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "safe", "discovery", "external" }
dependencies = { "ssl-cert" }

require("nmap")
require("shortport")
require("stdnse")
require("dns")


local get_cert = function(host, port)
    if nmap.registry[host.ip] and nmap.registry[host.ip][port] then
        return nmap.registry[host.ip][port]["ssl-cert"]
    end
end

local format_date = function(day_num)
    return os.date("%d %b %Y", 60 * 60 * 24 * tonumber(day_num))
end

portrule = shortport.ssl

action = function(host, port)
    local lines, sha1, query
    local cert = get_cert(host, port.number)

    if not cert then
        return nil
    end

    sha1 = stdnse.tohex(cert.digest(cert, "sha1"))
    query = sha1 .. ".certs.googlednstest.com"
    stdnse.print_debug("%s %s", SCRIPT_NAME, query)

    local status, decoded_response = dns.query(query, { dtype = "TXT" })

    lines = {}

    if status then
        local raw_start, raw_stop, delta = string.match(decoded_response, "(%d+) (%d+) (%d+)")
        local date_start, date_stop = format_date(raw_start), format_date(raw_stop)

        table.insert(lines, "First/last date seen: " .. date_start .. " / " .. date_stop)
        table.insert(lines, "Days in between: " .. tonumber(delta))
    else
        table.insert(lines, "No DB entry")
    end

    return stdnse.format_output(true, lines)
end

