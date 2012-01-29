description=[[
Sniffs an interface for HTTP traffic and dumps any URLs, and their originating
IP. Script output differs from other script as URLs are written to stdout
directly. There is also an option to log the results to file.

The script can be limited in time by using the timeout argument or run until a
ctrl+break is issued, which is the default.
]]

---
-- @usage
-- nmap --script url-snarf
--
-- @output
-- | url-snarf: 
-- |_  Sniffed 169 URLs in 5 seconds
--
-- @arg timeout runs the script until timeout is reached (defaul: infinite)
-- @arg nostdout doesn't write any output to stdout while running
-- @arg outfile filename to which all discovered URLs are written
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}

require 'packet'
require 'url'

local arg_iface = 	nmap.get_interface() or 
					stdnse.get_script_args(SCRIPT_NAME .. ".interface")

prerule = function()
 	local has_interface = ( arg_iface ~= nil )
	if not nmap.is_privileged() then
		stdnse.print_verbose("%s not running for lack of privileges.", SCRIPT_NAME)
		return false
	end
	if ( not(has_interface) ) then
		stdnse.print_verbose("%s no network interface was supplied, aborting ...", SCRIPT_NAME)
		return false
	end
	return true
end

-- we should probably leverage code from the http library, but those functions
-- are all declared local.
local function get_url(data)

	local headers, body = unpack(stdnse.strsplit("\r\n\r\n", data))
	if ( not(headers) ) then
		return
	end
	headers = stdnse.strsplit("\r\n", headers)
	if ( not(headers) or 1 > #headers ) then
		return
	end
	local parsed = {}
	parsed.path = headers[1]:match("^[^s%s]+ ([^%s]*) HTTP/1%.%d$")
	if ( not(parsed.path) ) then
		return
	end	
	for _, v in ipairs(headers) do
		parsed.host, parsed.port = v:match("^Host: (.*):?(%d?)$")
		if ( parsed.host ) then
			break
		end
	end
	if ( not(parsed.host) ) then
		return
	end
	parsed.port = ( #parsed.port ~= 0 )  and parsed.port or nil
	parsed.scheme = "http"
	local u = url.build(parsed)
	if ( not(u) ) then
		return
	end
	return u
end

local arg_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME..".timeout"))
local arg_nostdout= stdnse.get_script_args(SCRIPT_NAME..".nostdout")
local arg_outfile = stdnse.get_script_args(SCRIPT_NAME..".outfile")

local function log_entry(src_ip, url)
	local outfd = io.open(arg_outfile, "a")
	if ( outfd ) then
		local entry = ("%s\t%s\r\n"):format(src_ip, url)
		outfd:write(entry)
		outfd:close()
	end
end

action = function()
	local counter = 1
	
	if ( arg_outfile ) then
		local outfd = io.open(arg_outfile, "a")
		if ( not(outfd) ) then
			return ("\n  ERROR: Failed to open outfile (%s)"):format(arg_outfile)
		end
		outfd:close()
	end
		
	local socket = nmap.new_socket()
	socket:set_timeout(1000)
	socket:pcap_open(arg_iface, 1500, true, "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")

	local start, stop = os.time()
	repeat
		local status, len, _, l3 = socket:pcap_receive()
		if ( status ) then
			local p = packet.Packet:new( l3, #l3 )
			local pos = p.tcp_data_offset + 1
			local http_data = p.buf:sub(pos)

			local url = get_url(http_data)
			if ( url ) then
				counter = counter + 1
				if ( not(arg_nostdout) ) then
					print(p.ip_src, url)
				end
				if ( arg_outfile ) then
					log_entry(p.ip_src, url)
				end
			end
		end
		if ( arg_timeout and arg_timeout <= os.time() - start ) then
			stop = os.time()
			break
		end
	until(false)
	return ("\n  Sniffed %d URLs in %d seconds"):format(counter, stop - start)
end
