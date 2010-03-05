description = [[
Attempts to enumerate network interfaces through SNMP
]]

---
-- @output
-- | snmp-interfaces:  
-- |   eth0
-- |_    IP address: 192.168.128.15
--
-- 


author = "Thomas Buchanan"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- code borrowed heavily from Patrik Karlsson's excellent snmp scripts
-- Created 03/03/2010 - v0.1 - created by Thomas Buchanan <tbuchanan@thecompassgrp.net>

require "shortport"
require "snmp"
require "datafiles"

portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

--- Walks the MIB Tree
--
-- @param socket socket already connected to the server
-- @base_oid string containing the base object ID to walk
-- @return table containing <code>oid</code> and <code>value</code>
function snmp_walk( socket, base_oid )
	
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)	

	local snmp_table = {}
	local oid = base_oid
	
	while ( true ) do
		
		local value, response, snmpdata, options, item = nil, nil, nil, {}, {}
		options.reqId = 28428 -- unnecessary?
		payload = snmp.encode( snmp.buildPacket( snmp.buildGetNextRequest(options, oid) ) )

		try(socket:send(payload))
		response = try( socket:receive_bytes(1) )
	
		snmpdata = snmp.fetchResponseValues( response )
		
		value = snmpdata[1][1]
		oid  = snmpdata[1][2]
		
		if not oid:match( base_oid ) or base_oid == oid then
			break
		end
		
		item.oid = oid
		item.value = value
		
		table.insert( snmp_table, item )
				
	end

	socket:close()
	snmp_table.baseoid = base_oid

	return snmp_table
	
end

--- Gets a value for the specified oid
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @param oid string containing the object id for which the value should be extracted
-- @return value of relevant type or nil if oid was not found
function get_value_from_table( tbl, oid )
	
	for _, v in ipairs( tbl ) do
		if v.oid == oid then
			return v.value
		end
	end
	
	return nil
end

--- Gets the network interface type from a list of IANA approved types
-- Taken from IANAifType-MIB 
-- Available at http://www.iana.org/assignments/ianaiftype-mib
-- REVISION     "201002110000Z"
--
-- @param iana integer interface type returned from snmp result
-- @return string description of interface type, or "Unknown" if type not found
function get_iana_type( iana )
	-- 254 types are currently defined
	-- if the requested type falls outside that range, reset to "other"
	if iana > 254 or iana < 1 then
		iana = 1
	end
	
	local iana_types = { "other", "regular1822", "hdh1822", "ddnX25", "rfc877x25", "ethernetCsmacd", 
	"iso88023Csmacd", "iso88024TokenBus", "iso88025TokenRing", "iso88026Man", "starLan",
	"proteon10Mbit", "proteon80Mbit", "hyperchannel", "fddi", "lapb", "sdlc", "ds1", "e1", 
	"basicISDN", "primaryISDN", "propPointToPointSerial", "ppp", "softwareLoopback", "eon", 
	"ethernet3Mbit", "nsip", "slip", "ultra", "ds3", "sip", "frameRelay", "rs232", "para", 
	"arcnet", "arcnetPlus", "atm", "miox25", "sonet", "x25ple", "iso88022llc", "localTalk", 
	"smdsDxi", "frameRelayService", "v35", "hssi", "hippi", "modem", "aal5", "sonetPath", 
	"sonetVT", "smdsIcip", "propVirtual", "propMultiplexor", "ieee80212", "fibreChannel", 
	"hippiInterface", "frameRelayInterconnect", "aflane8023", "aflane8025", "cctEmul", 
	"fastEther", "isdn", "v11", "v36", "g703at64k", "g703at2mb", "qllc", "fastEtherFX", 
	"channel", "ieee80211", "ibm370parChan", "escon", "dlsw", "isdns", "isdnu", "lapd", 
	"ipSwitch", "rsrb", "atmLogical", "ds0", "ds0Bundle", "bsc", "async", "cnr", 
	"iso88025Dtr", "eplrs", "arap", "propCnls", "hostPad", "termPad", "frameRelayMPI", 
	"x213", "adsl", "radsl", "sdsl", "vdsl", "iso88025CRFPInt", "myrinet", "voiceEM", 
	"voiceFXO", "voiceFXS", "voiceEncap", "voiceOverIp", "atmDxi", "atmFuni", "atmIma", 
	"pppMultilinkBundle", "ipOverCdlc", "ipOverClaw", "stackToStack", "virtualIpAddress", 
	"mpc", "ipOverAtm", "iso88025Fiber", "tdlc", "gigabitEthernet", "hdlc", "lapf", "v37", 
	"x25mlp", "x25huntGroup", "trasnpHdlc", "interleave", "fast", "ip", "docsCableMaclayer", 
	"docsCableDownstream", "docsCableUpstream", "a12MppSwitch", "tunnel", "coffee", "ces", 
	"atmSubInterface", "l2vlan", "l3ipvlan", "l3ipxvlan", "digitalPowerlinev", "mediaMailOverIp", 
	"dtm", "dcn", "ipForward", "msdsl", "ieee1394", "if-gsn", "dvbRccMacLayer", "dvbRccDownstream", 
	"dvbRccUpstream", "atmVirtual", "mplsTunnel", "srp", "voiceOverAtm", "voiceOverFrameRelay", 
	"idsl", "compositeLink", "ss7SigLink", "propWirelessP2P", "frForward", "rfc1483", "usb", 
	"ieee8023adLag", "bgppolicyaccounting", "frf16MfrBundle", "h323Gatekeeper", "h323Proxy", 
	"mpls", "mfSigLink", "hdsl2", "shdsl", "ds1FDL", "pos", "dvbAsiIn", "dvbAsiOut", "plc", 
	"nfas", "tr008", "gr303RDT", "gr303IDT", "isup", "propDocsWirelessMaclayer", 
	"propDocsWirelessDownstream", "propDocsWirelessUpstream", "hiperlan2", "propBWAp2Mp", 
	"sonetOverheadChannel", "digitalWrapperOverheadChannel", "aal2", "radioMAC", "atmRadio", 
	"imt", "mvl", "reachDSL", "frDlciEndPt", "atmVciEndPt", "opticalChannel", "opticalTransport", 
	"propAtm", "voiceOverCable", "infiniband", "teLink", "q2931", "virtualTg", "sipTg", "sipSig", 
	"docsCableUpstreamChannel", "econet", "pon155", "pon622", "bridge", "linegroup", "voiceEMFGD", 
	"voiceFGDEANA", "voiceDID", "mpegTransport", "sixToFour", "gtp", "pdnEtherLoop1", 
	"pdnEtherLoop2", "opticalChannelGroup", "homepna", "gfp", "ciscoISLvlan", "actelisMetaLOOP", 
	"fcipLink", "rpr", "qam", "lmp", "cblVectaStar", "docsCableMCmtsDownstream", "adsl2", 
	"macSecControlledIF", "macSecUncontrolledIF", "aviciOpticalEther", "atmbond", "voiceFGDOS", 
	"mocaVersion1", "ieee80216WMAN", "adsl2plus", "dvbRcsMacLayer", "dvbTdm", "dvbRcsTdma", 
	"x86Laps", "wwanPP", "wwanPP2", "voiceEBS", "ifPwType", "ilan", "pip", "aluELP", "gpon", 
	"vdsl2", "capwapDot11Profile", "capwapDot11Bss", "capwapWtpVirtualRadio" }
	
	return iana_types[iana]
end

--- Calculates the speed of the interface based on the snmp value
-- 
-- @param speed value from IF-MIB::ifSpeed
-- @return string description of speed
function get_if_speed( speed )
	local result
	
	-- GigE or 10GigE speeds
	if speed >= 1000000000 then
		result = string.format( "%d Gbps", speed / 1000000000)
	-- Common for 10 or 100 Mbit ethernet
	elseif speed >= 1000000 then
		result = string.format( "%d Mbps", speed / 1000000)
	-- Anything slower report in Kbps
	else
		result = string.format( "%d Kbps", speed / 1000)
	end
	
	return result
end

--- Calculates the amount of traffic passed through an interface based on the snmp value
-- 
-- @param amount value from IF-MIB::ifInOctets or IF-MIB::ifOutOctets
-- @return string description of traffic amount
function get_traffic( amount )
	local result
	
	-- Gigabytes
	if amount >= 1000000000 then
		result = string.format( "%.2f Gb", amount / 1000000000)
	-- Megabytes
	elseif amount >= 1000000 then
		result = string.format( "%.2f Mb", amount / 1000000)
	-- Anything lower report in kb
	else
		result = string.format( "%.2f Kb", amount / 1000)
	end
	
	return result
end

--- Converts a 6 byte string into the familiar MAC address formatting
--
-- @param mac string containing the MAC address
-- @return formatted string suitable for printing
function get_mac_addr( mac )
	local catch = function() return end
	local try = nmap.new_try(catch)
	-- Build the MAC prefix lookup table
	if not nmap.registry.snmp_interfaces then
		-- Create the table in the registry so we can share between script instances
		nmap.registry.snmp_interfaces = {}
		nmap.registry.snmp_interfaces.mac_prefixes = try(datafiles.parse_mac_prefixes())
	end
	
	if mac:len() ~= 6 then
		return "Unknown"
	else
		local prefix = string.upper(string.format("%02x%02x%02x", mac:byte(1), mac:byte(2), mac:byte(3)))
		local manuf = nmap.registry.snmp_interfaces.mac_prefixes[prefix] or "Unknown"
		return string.format("%02x:%02x:%02x:%02x:%02x:%02x (%s)", mac:byte(1), mac:byte(2), mac:byte(3), mac:byte(4), mac:byte(5), mac:byte(6), manuf )
	end
end

--- Processes the list of network interfaces
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table with network interfaces described in key / value pairs
function process_interfaces( tbl )
	
	-- Add the %. escape character to prevent matching the index on e.g. "1.3.6.1.2.1.2.2.1.10."
	local if_index = "1.3.6.1.2.1.2.2.1.1%."
	local if_descr = "1.3.6.1.2.1.2.2.1.2%."
	local if_type = "1.3.6.1.2.1.2.2.1.3%."
	local if_speed = "1.3.6.1.2.1.2.2.1.5%."
	local if_phys_addr = "1.3.6.1.2.1.2.2.1.6%."
	local if_status = "1.3.6.1.2.1.2.2.1.8%."
	local if_in_octets = "1.3.6.1.2.1.2.2.1.10%."
	local if_out_octets = "1.3.6.1.2.1.2.2.1.16%."
	local new_tbl = {}
	
	-- Some operating systems (such as MS Windows) don't list interfaces with consecutive indexes
	-- Therefore we keep an index list so we can iterate over the indexes later on
	new_tbl.index_list = {}
	
	for _, v in ipairs( tbl ) do
		
		if ( v.oid:match("^" .. if_index) ) then
			local item = {}
			item.index = get_value_from_table( tbl, v.oid )
			
			local objid = v.oid:gsub( "^" .. if_index, if_descr) 
			local value = get_value_from_table( tbl, objid )
			
			if value and value:len() > 0 then
				item.descr = value
			end
			
			objid = v.oid:gsub( "^" .. if_index, if_type ) 
			value = get_value_from_table( tbl, objid )
			
			if value then
				item.type = get_iana_type(value)
			end
	
			objid = v.oid:gsub( "^" .. if_index, if_speed ) 
			value = get_value_from_table( tbl, objid )
			
			if value then
				item.speed = get_if_speed( value )
			end
			
			objid = v.oid:gsub( "^" .. if_index, if_phys_addr ) 
			value = get_value_from_table( tbl, objid )
						
			if value and value:len() > 0 then
				item.phys_addr = get_mac_addr( value )
			end
			
			objid = v.oid:gsub( "^" .. if_index, if_status ) 
			value = get_value_from_table( tbl, objid )
			
			if value == 1 then
				item.status = "up"
			elseif value == 2 then
				item.status = "down"
			end
	
			objid = v.oid:gsub( "^" .. if_index, if_in_octets ) 
			value = get_value_from_table( tbl, objid )
			
			if value then
				item.received = get_traffic( value )
			end
			
			objid = v.oid:gsub( "^" .. if_index, if_out_octets ) 
			value = get_value_from_table( tbl, objid )
			
			if value then
				item.sent = get_traffic( value )
			end
				
			new_tbl[item.index] = item
			-- Add this interface index to our master list
			table.insert( new_tbl.index_list, item.index )
			
		end
	
	end
	
	return new_tbl
	
end

--- Processes the list of network interfaces and finds associated IP addresses
--
-- @param if_tbl table containing network interfaces
-- @param ip_tbl table containing <code>oid</code> and <code>value</code> pairs from IP::MIB
-- @return table with network interfaces described in key / value pairs
function process_ips( if_tbl, ip_tbl )
	local ip_index = "1.3.6.1.2.1.4.20.1.2."
	local ip_addr = "1.3.6.1.2.1.4.20.1.1."
	local ip_netmask = "1.3.6.1.2.1.4.20.1.3."
	local index
	local item
	
	for _, v in ipairs( ip_tbl ) do
		if ( v.oid:match("^" .. ip_index) ) then
			index = get_value_from_table( ip_tbl, v.oid )
			item = if_tbl[index]
			
			local objid = v.oid:gsub( "^" .. ip_index, ip_addr ) 
			local value = get_value_from_table( ip_tbl, objid )
			
			if value then
				item.ip_addr = value
			end
			
			objid = v.oid:gsub( "^" .. ip_index, ip_netmask ) 
			value = get_value_from_table( ip_tbl, objid )
			
			if value then
				item.netmask = value
			end
		end
	end
	
	return if_tbl
end

--- Process the table of network interfaces for reporting
--
-- @param tbl table containing network interfaces
-- @return table suitable for <code>stdnse.format_output</code>
function build_results( tbl )
	local new_tbl = {}
	local verbose = nmap.verbosity()
	
	-- For each interface index previously discovered, format the relevant information for output
	for _, index in ipairs( tbl.index_list ) do
		local interface = tbl[index]
		local item = {}
		local status = interface.status
		local if_type = interface.type
		
		-- If no verbose flags are present, only print interfaces that are active, and don't show too many details
		-- Also, ignore software loopback interfaces
		if (verbose < 1) and (status == "up") and ( if_type ~= "softwareLoopback") then
			if interface.descr then
				item.name = interface.descr
			else
				item.name = string.format("Interface %d", item.index)
			end
			if interface.ip_addr then
				table.insert( item, ("IP address: %s"):format( interface.ip_addr ) )
			end
		elseif verbose > 0 then
			if interface.descr then
				item.name = interface.descr
			else
				item.name = string.format("Interface %d", item.index)
			end
			
			if interface.ip_addr and interface.netmask then
				table.insert( item, ("IP address: %s/%s"):format( interface.ip_addr, interface.netmask ) )
			end
			
			if interface.phys_addr then
				table.insert( item, ("MAC address: %s"):format( interface.phys_addr ) )
			end
			
			if interface.type and interface.speed then
				table.insert( item, ("Type: %s (%s)"):format( interface.type, interface.speed ) )
			end
			
			if interface.status then
				table.insert( item, ("Status: %s"):format( interface.status ) )
			end
			
			if interface.sent and interface.received then
				table.insert( item, ("Traffic stats: %s sent, %s received"):format( interface.sent, interface.received ) )
			end
		end
		table.insert( new_tbl, item )
	end
	
	return new_tbl
end		

action = function(host, port)

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	-- IF-MIB - used to look up network interfaces
	local if_oid = "1.3.6.1.2.1.2.2.1"
	-- IP-MIB - used to determine IP address information
	local ip_oid = "1.3.6.1.2.1.4.20"
	local interfaces = {}
	local ips = {}

	socket:set_timeout(5000)
	try(socket:connect(host.ip, port.number, "udp"))
	
	-- retreive network interface information from IF-MIB
	interfaces = snmp_walk( socket, if_oid )

	if ( interfaces == nil ) or ( #interfaces == 0 ) then
		return
	end
	
	stdnse.print_debug("SNMP walk of IF-MIB returned %d lines", #interfaces)
	
	-- build a table of network interfaces from the IF-MIB table
	interfaces = process_interfaces( interfaces )
	
	-- retreive IP address information from IP-MIB
	try(socket:connect(host.ip, port.number, "udp"))
	ips = snmp_walk( socket, ip_oid )
	
	-- associate that IP address information with the correct interface
	if ( ips ~= nil ) and ( #ips ~= 0 ) then
		interfaces = process_ips( interfaces, ips )
	end

	nmap.set_port_state(host, port, "open")
	
	interfaces = build_results( interfaces )
	
	return stdnse.format_output( true, interfaces )
end
