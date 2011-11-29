description = [[
Compares the detected service on a port against the expected service and
reports deviations. The script requires that a version scan has been run in
order to be able to discover what service is running on each port.
]]

---
-- @usage
-- nmap --script unusual-port <ip>
--
-- @output
-- 23/tcp open   ssh     OpenSSH 5.8p1 Debian 7ubuntu1 (protocol 2.0)
-- |_unusual-port: ssh unexpected on port tcp/23
-- 25/tcp open   smtp    Postfix smtpd
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "safe" }

require 'datafiles'

portrule = function() return true end
hostrule = function() return true end

-- the hostrule is only needed to warn 
hostaction = function(host)
	local port, state = nil, "open"
	local is_version_scan = false

	-- iterate over ports and check whether name_confidence > 3 this would
	-- suggest that a version scan has been run
	for _, proto in ipairs({"tcp", "udp"}) do
		repeat
			port = nmap.get_ports(host, port, proto, state)
			if ( port and port.version.name_confidence > 3 ) then
				is_version_scan = true
				break
			end
		until( not(port) )
	end

	-- if no version scan has been run, warn the user as the script requires a
	-- version scan in order to work.
	if ( not(is_version_scan) ) then
		return stdnse.format_output(true, "WARNING: this script depends on Nmap's service/version detection (-sV)")
	end
	
end

portchecks = {
	
	['tcp'] = {
		[113] = function(host, port) return ( port.service == "ident" ) end,
		[445] = function(host, port) return ( port.service == "netbios-ssn" ) end,
		[587] = function(host, port) return ( port.service == "smtp" ) end,
		[593] = function(host, port) return ( port.service == "ncacn_http" ) end,
		[636] = function(host, port) return ( port.service == "ldapssl" ) end,
		[3268] = function(host, port) return ( port.service == "ldap" ) end,
	},
	
	['udp'] = {
		[5353] = function(host, port) return ( port.service == "mdns" ) end,
	}

}

servicechecks = {
	['http'] = function(host, port)
		local service = port.service
		port.service = "unknown"
		local status = shortport.http(host, port)
		port.service = service
		return status
	end,
	
	-- accept msrpc on any port for now, we might want to limit it to certain
	-- port ranges in the future.
	['msrpc'] = function(host, port) return true end,
	
	-- accept ncacn_http on any port for now, we might want to limit it to
	-- certain port ranges in the future.
	['ncacn_http'] = function(host, port) return true end,
}

local function checkService(host, port)
	local ok = false

	if ( port.version.name_confidence <= 3 ) then
		return
	end
	if ( portchecks[port.protocol][port.number] ) then
		ok = portchecks[port.protocol][port.number](host, port)
	end
	if ( not(ok) and servicechecks[port.service] ) then
		ok = servicechecks[port.service](host, port)
	end
	if ( not(ok) and port.service and 
		( port.service == nmap.registry[SCRIPT_NAME]['services'][port.protocol][port.number] or
		  "unknown" == nmap.registry[SCRIPT_NAME]['services'][port.protocol][port.number] or
		  not(nmap.registry[SCRIPT_NAME]['services'][port.protocol][port.number]) ) ) then
		ok = true
	end	
	if ( not(ok) ) then
		return ("%s unexpected on port %s/%d"):format(port.service, port.protocol, port.number)
	end
end

local function loadTables()
	for _, proto in ipairs({"tcp","udp"}) do
		if ( not(nmap.registry[SCRIPT_NAME]['services'][proto]) ) then
			local status, svc_table = datafiles.parse_services(proto)
			if ( status ) then
				nmap.registry[SCRIPT_NAME]['services'][proto] = svc_table
			end	
		end
	end
end

portaction = function(host, port)
	nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
	nmap.registry[SCRIPT_NAME]['services'] = nmap.registry[SCRIPT_NAME]['services'] or {}
	loadTables()
	return checkService(host, port)
end

local Actions = {
  hostrule = hostaction,
  portrule = portaction
}

-- execute the action function corresponding to the current rule
action = function(...) return Actions[SCRIPT_TYPE](...) end
