description = [[
Check for vulnerabilities:
* MS08-067, a Windows RPC vulnerability
* Conficker, an infection by the Conficker worm
* Unnamed regsvc DoS, a denial-of-service vulnerability I accidentically found in Windows 2003

WARNING: These checks are dangerous, and are very likely to bring down a server. 
These should not be run in a production environment unless you (and, more importantly,
the business) understand the risks! 

As a system administrator, performing these kinds of checks is crucial, because 
a lot more damage can be done by a worm or a hacker using this vulnerability than
by a scanner. Penetration testers, on the other hand, might not want to use this
script -- crashing services is not generally a good way of sneaking through a 
network. 

If you set the script parameter 'unsafe', then scripts will run that are almost 
(or totally) guaranteed to crash a vulnerable system; do NOT specify <code>unsafe</code>
in a production environment! And that isn't to say that non-unsafe scripts will 
not crash a system, they're just less likely to. 

If you set the script parameter 'safe', then script will run that rarely or never
crash a vulnerable system. No promises, though. 

MS08-067 -- Checks if a host is vulnerable to MS08-067, a Windows RPC vulnerability that
can allow remote code execution.  Checking for MS08-067 is very dangerous, as the check 
is likely to crash systems. On a fairly wide scan conducted by Brandon Enright, we determined
that on average, a vulnerable system is more likely to crash than to survive
the check. Out of 82 vulnerable systems, 52 crashed. 

At the same time, MS08-067 is extremely critical to fix. Metasploit has a working and
stable exploit for it, and any system vulnerable can very easily be compromised. 

Conficker -- Checks if a host is infected with a known Conficker strain. This check
is based on the simple conficker scanner found on this page:
http://iv.cs.uni-bonn.de/wg/cs/applications/containing-conficker
Thanks to the folks who wrote that scanner!

regsvc DoS -- Checks if a host is vulnerable to a crash in regsvc, caused 
by a null pointer dereference. I inadvertently discovered this crash while working
on <code>smb-enum-sessions</code>, and discovered that it was repeatable. It's been 
reported to Microsoft (case #MSRC8742). 

This check WILL crash the service, if it's vulnerable, and requires a guest account
or higher to work. It is considered <code>unsafe</code>. 

(Note: if you have other SMB/MSRPC vulnerability checks you'd like to see added, and
you can show me a tool with a license that is compatible with Nmap's, post a request 
on the Nmap-dev mailing list and I'll add it to my list [Ron Bowes]). 
]]
---
--@usage
-- nmap --script smb-check-vulns.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-check-vulns.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- |  smb-check-vulns:
-- |  MS08-067: FIXED
-- |  Conficker: Likely INFECTED
-- |_ regsvc DoS: VULNERABLE
--
-- @args unsafe If set, this script will run checks that, if the system isn't
--       patched, are basically guaranteed to crash something. Remember that
--       non-unsafe checks aren't necessarily safe either)
-- @args safe   If set, this script will only run checks that are known (or at
--       least suspected) to be safe. 
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive"}
-- Set the runlevel to >2 so this runs last (so if it DOES crash something, it doesn't
-- till other scans have had a chance to run)
runlevel = 2

require 'msrpc'
require 'smb'
require 'stdnse'

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

local VULNERABLE = 1
local PATCHED    = 2
local UNKNOWN    = 3
local NOTRUN     = 4
local INFECTED   = 5
local CLEAN      = 6

---Check if the server is patched for MS08-067. This is done by calling NetPathCompare with an 
-- illegal string. If the string is accepted, then the server is vulnerable; if it's rejected, then
-- you're safe (for now). 
--
-- Based on a packet cap of this script, thanks go out to the author:
-- http://labs.portcullis.co.uk/download/ms08-067_check.py 
--
-- If there's a licensing issue, please let me (Ron Bowes) know so I can 
--
-- NOTE: This CAN crash stuff (ie, crash svchost and force a reboot), so beware! In about 20 
-- tests I did, it crashed once. This is not a guarantee. 
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error code; otherwise, result is either 
--        <code>VULNERABLE</code> for vulnerable, <code>PATCHED</code> for not vulnerable, 
--        <code>UNKNOWN</code> if there was an error (likely vulnerable), <code>NOTRUN</code>
--        if this check was disabled, and <code>INFECTED</code> if it was patched by Conficker. 
function check_ms08_067(host)
	if(nmap.registry.args.safe ~= nil) then
		return true, NOTRUN
	end
	local status, smbstate
	local bind_result, netpathcompare_result

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, "\\\\BROWSER")
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SRVSVC service
	status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Call netpathcanonicalize
--	status, netpathcanonicalize_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, "\\a", "\\test\\")
	
	local path1 = "\\AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\..\\n"
	local path2 = "\\n"
	status, netpathcompare_result = msrpc.srvsvc_netpathcompare(smbstate, host.ip, path1, path2, 1, 0)

	-- Stop the SMB session
	msrpc.stop_smb(smbstate)

	if(status == false) then
		if(string.find(netpathcompare_result, "UNKNOWN_57") ~= nil) then
			return true, INFECTED
		elseif(string.find(netpathcompare_result, "INVALID_NAME") ~= nil) then
			return true, PATCHED
		else
io.write(string.format("\n\n%s\n\n", netpathcompare_result))
			return true, UNKNOWN
		end
	end


	return true, VULNERABLE
end

-- Help messages for the more common errors seen by the Conficker check.
CONFICKER_ERROR_HELP = {
	-- http://seclists.org/nmap-dev/2009/q1/0918.html "non-Windows boxes (Samba on Linux/OS X, or a printer)"
	-- http://www.skullsecurity.org/blog/?p=209#comment-156
	--   "That means either it isn’t a Windows machine, or the service is
	--    either crashed or not running. That may indicate a failed (or
	--    successful) exploit attempt, or just a locked down system.
	--    NT_STATUS_OBJECT_NAME_NOT_FOUND can be returned if the browser
	--    service is disabled. There are at least two ways that can happen:
	--    1) The service itself is disabled in the services list.
	--    2) The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Browser\Parameters\MaintainServerList
	--       is set to Off/False/No rather than Auto or yes.
	--    On these systems, if you reenable the browser service, then the
	--    test will complete."
	["NT_STATUS_OBJECT_NAME_NOT_FOUND"] = 
[[UNKNOWN; not Windows, or Windows with disabled browser service (CLEAN); or Windows with crashed browser service (possibly INFECTED).
|  If you know the remote system is Windows, try rebooting it and scanning
|_ again. (Error NT_STATUS_OBJECT_NAME_NOT_FOUND)]],
	-- http://www.skullsecurity.org/blog/?p=209#comment-100
	--   "That likely means that the server has been locked down, so we
	--    don’t have access to the necessary pipe. Fortunately, that means
	--    that neither does Conficker — NT_STATUS_ACCESS_DENIED probably
	--    means you’re ok."
	["NT_STATUS_ACCESS_DENIED"] =
[[Likely CLEAN; access was denied.
|  If you have a login, try using --script-args=smbuser=xxx,smbpass=yyy
|  (replace xxx and yyy with your username and password). Also try
|_ smbdomain=zzz if you know the domain. (Error NT_STATUS_ACCESS_DENIED)]],
	-- The cause of these two is still unknown.
	-- ["NT_STATUS_NOT_SUPPORTED"] =
	-- [[]]
	-- http://thatsbroken.com/?cat=5 (doesn't seem common)
	-- ["NT_STATUS_REQUEST_NOT_ACCEPTED"] =
	-- [[]]
}

---Check if the server is infected with Conficker. This can be detected by a modified MS08-067 patch, 
-- which rejects a different illegal string than the official patch rejects. 
--
-- Based loosely on the Simple Conficker Scanner, found here:
-- http://iv.cs.uni-bonn.de/wg/cs/applications/containing-conficker/
--
-- If there's a licensing issue, please let me (Ron Bowes) know so I can fix it
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error code; otherwise, result is either 
--        <code>INFECTED</code> for infected or <code>CLEAN</code> for not infected.
function check_conficker(host)
	local status, smbstate
	local bind_result, netpathcompare_result

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, "\\\\BROWSER")
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SRVSVC service
	status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Call netpathcanonicalize
--	status, netpathcanonicalize_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, "\\a", "\\test\\")
	
	local path = "\\..\\"
	local error_result
	status, netpathcanonicalize_result, error_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, path)

	-- Stop the SMB session
	msrpc.stop_smb(smbstate)

	if(status == false) then
		if(string.find(netpathcanonicalize_result, "INVALID_NAME")) then
			return true, CLEAN
		--elseif(string.find(netpathcanonicalize_result, "UNKNOWN_57") ~= nil and error_result['can_path'] == 0x5c450000) then
		elseif(string.find(netpathcanonicalize_result, "UNKNOWN_57") ~= nil) then
			return true, INFECTED
		else
			local help = CONFICKER_ERROR_HELP[netpathcanonicalize_result] or "UNKNOWN (can't determine infection); got error " .. netpathcanonicalize_result
			return false, help
		end
	end


	return true, CLEAN
end

---While writing <code>smb-enum-sessions</code> I discovered a repeatable null-pointer dereference 
-- in regsvc. I reported it to Microsoft, but because it's a simple DoS (and barely even that, because
-- the service automatically restarts), and because it's only in Windows 2000, it isn't likely that they'll
-- fix it. This function checks for that crash (by crashing the process). 
--
-- The crash occurs when the string sent to winreg_enumkey() function is null. 
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error code; otherwise, result is either 
--        <code>VULNERABLE</code> for vulnerable or <code>PATCHED</code> for not vulnerable. If the check
--        was skipped, <code>NOTRUN</code> is returned. 
function check_winreg_Enum_crash(host)
	if(nmap.registry.args.safe ~= nil) then
		return true, NOTRUN
	end
	if(nmap.registry.args.unsafe == nil) then
		return true, NOTRUN
	end

	local i, j
	local elements = {}

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.WINREG_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to WINREG service
	status, bind_result = msrpc.bind(smbstate, msrpc.WINREG_UUID, msrpc.WINREG_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	status, openhku_result = msrpc.winreg_openhku(smbstate)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, openhku_result
	end

	-- Loop through the keys under HKEY_USERS and grab the names
	status, enumkey_result = msrpc.winreg_enumkey(smbstate, openhku_result['handle'], 0, nil)
	msrpc.stop_smb(smbstate)

	if(status == false) then
		return true, VULNERABLE
	end

	return true, PATCHED
end


action = function(host)

	local status, result
	local response = " \n"
	local found = false

	-- Check for ms08-067
	status, result = check_ms08_067(host)
	if(status == false) then
		if(nmap.debugging() > 0) then
			response = response .. "MS08-067: ERROR: " .. result .. "\n"
		end
	else
		if(result == VULNERABLE) then
			response = response .. "MS08-067: VULNERABLE\n"
			found = true
		elseif(result == UNKNOWN) then
			response = response .. "MS08-067: LIKELY VULNERABLE (host stopped responding)\n"
		elseif(result == NOTRUN) then
			response = response .. "MS08-067: Check disabled (remove 'safe=1' argument to run)\n"
		elseif(result == INFECTED) then
			response = response .. "MS08-067: PATCHED (possibly by Conficker)\n"
		else
			if(nmap.verbosity() > 0) then
				response = response .. "MS08-067: FIXED\n"
			end
		end
	end

	-- Check for Conficker
	status, result = check_conficker(host)
	if(status == false) then
		if(result == "NT_STATUS_BAD_NETWORK_NAME") then
			response = response .. "Conficker: ERROR: Network name not found (required service has crashed)\n"
		else
			response = response .. "Conficker: " .. result .. "\n"
		end
	else
		if(result == CLEAN) then
			response = response .. "Conficker: Likely CLEAN\n"
		else
			response = response .. "Conficker: Likely INFECTED\n"
			found = true
		end
	end

	-- Check for a winreg_Enum crash
	status, result = check_winreg_Enum_crash(host)
	if(status == false) then
		if(nmap.debugging() > 0) then
			response = response .. "regsvc DoS: ERROR: " .. result .. "\n"
		end
	else
		if(result == VULNERABLE) then
			response = response .. "regsvc DoS: VULNERABLE\n"
			found = true
		elseif(result == NOTRUN) then
			if(nmap.verbosity() > 0) then
				response = response .. "regsvc DoS: Check disabled (add --script-args=unsafe=1 to run)\n"
			end
		else
			if(nmap.verbosity() > 0) then
				response = response .. "regsvc DoS: FIXED\n"
			end
		end
	end

	-- Don't show a response if we aren't verbose and we found nothing
	if(nmap.verbosity() == 0 and found == false) then
		response = nil
	end

	return response
end



