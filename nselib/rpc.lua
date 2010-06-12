---
-- RPC Library supporting a very limited subset of operations
--
-- Summary
-- -------
-- 	o The library works over both the UDP and TCP protocols
--	o A subset of nfs and mountd procedures are supported
--  o The versions 1 through 3 are supported for the nfs and mountd program
--  o Authentication is supported using the NULL RPC Authentication protocol
--
-- Overview
-- --------
-- The library contains the following classes:
--   o Comm 
--   		- Handles network connections
--		- Handles low-level packet sending, recieving, decoding and encoding
--		- Stores rpc programs info: socket, protocol, program name, id and version
--		- Used by Mount, NFS, RPC and Portmap
--   o Portmap
--		- Containes RPC constants
--		- Handles communication with the portmap RPC program
--   o Mount 
--		- Handles communication with the mount RPC program
--   o NFS 
--		- Handles communication with the nfs RPC program
--   o Helper 
--		- Provides easy access to common RPC functions
--		- Implemented as a static class where most functions accept host 
--                and port parameters
--   o Util
--	 	- Mostly static conversion routines
--
-- The portmapper dynamically allocates tcp/udp ports to RPC programs. So in
-- in order to request a list of NFS shares from the server we need to:
--  o Make sure that we can talk to the portmapper on port 111 tcp or udp
--  o Query the portmapper for the ports allocated to the NFS program
--  o Query the NFS program for a list of shares on the ports returned by the
--    portmap program.
--
-- The Helper class contains functions that facilitate access to common
-- RPC program procedures through static class methods. Most functions accept
-- host and port parameters. As the Helper functions query the portmapper to
-- get the correct RPC program port, the port supplied to these functions
-- should be the rpcbind port 111/tcp or 111/udp.
--
-- Example
-- -------
-- The following sample code illustrates how scripts can use the Helper class
-- to interface the library:
--
-- <code>
-- -- retrieve a list of NFS export
-- status, mounts = rpc.Helper.ShowMounts( host, port )
--
-- -- iterate over every share
-- for _, mount in ipairs( mounts ) do
--
-- 	-- get the NFS attributes for the share
--	status, attribs = rpc.Helper.GetAttributes( host, port, mount.name )
--		.... process NFS attributes here ....
--  end
-- </code>
--
-- Additional information
-- ----------------------
-- RPC transaction ID's (XID) are not properly implemented as a random ID is
-- generated for each client call. The library makes no attempt to verify
-- whether the returned XID is valid or not.
--
-- Therefore TCP is the preferred method of communication and the library
-- always attempts to connect to the TCP port of the RPC program first.
-- This behaviour can be overrided by setting the rpc.protocol argument.
-- The portmap service is always queried over the protocol specified in the
-- port information used to call the Helper function from the script.
--
-- When multiple versions exists for a specific RPC program the library
-- always attempts to connect using the highest available version.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
--
-- @args nfs.version number If set overrides the detected version of nfs
-- @args mount.version number If set overrides the detected version of mountd
-- @args rpc.protocol table If set overrides the preferred order in which
--       protocols are tested. (ie. "tcp", "udp")

module(... or "rpc", package.seeall)
require("datafiles")

-- Version 0.3
--
-- Created 01/24/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net> 
-- Revised 02/22/2010 - v0.2 - cleanup, revised the way TCP/UDP are handled fo
--                             encoding an decoding
-- Revised 03/13/2010 - v0.3 - re-worked library to be OO
-- Revised 04/18/2010 - v0.4 - Applied patch from Djalal Harouni with improved 
--                             error checking and re-designed Comm class. see:
--                             http://seclists.org/nmap-dev/2010/q2/232
-- Revised 06/02/2010 - v0.5 - added code to the Util class to check for file
--                             types and permissions.
-- Revised 06/04/2010 - v0.6 - combined Portmap and RPC classes in the
--                             same Portmap class.
--


-- RPC args using the nmap.registry.args
RPC_args = {
	["rpcbind"] = { proto = 'rpc.protocol' },
	["nfs"] = { ver = 'nfs.version' },
	["mountd"] = { ver = 'mount.version' },
}

-- Defines the order in which to try to connect to the RPC programs
-- TCP appears to be more stable than UDP in most cases, so try it first
local RPC_PROTOCOLS = (nmap.registry.args and nmap.registry.args[RPC_args['rpcbind'].proto] and 
			type(nmap.registry.args[RPC_args['rpcbind'].proto]) == 'table') and
			nmap.registry.args[RPC_args['rpcbind'].proto] or { "tcp", "udp" }

-- used to cache the contents of the rpc datafile
local RPC_PROGRAMS

-- local mutex to synchronize I/O operations on nmap.registry[host.ip]['portmap']
local mutex = nmap.mutex("rpc")

-- Supported protocol versions
RPC_version = {
	["rpcbind"] = { min=2, max=2 },
	["nfs"] = { min=1, max=3 },
	["mountd"] = { min=1, max=3 },
}

math.randomseed( os.time() )

-- Low-level communication class
Comm = {

	--- Creats a new rpc Comm object
	--
	-- @param program name string
	-- @param version number containing the program version to use
	-- @return a new Comm object
	new = function(self, program, version)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.program = program
		o.program_id = Util.ProgNameToNumber(program)
		o:SetVersion(version)
		return o
	end,

	--- Connects to the remote program
	--
	-- @param host table
	-- @param port table
	-- @return status boolean true on success, false on failure
	-- @return string containing error message (if status is false)
	Connect = function(self, host, port)
		local status, err, socket
		status, err = self:ChkProgram()
		if (not(status)) then
			return status, err
		end
		status, err = self:ChkVersion()
		if (not(status)) then
			return status, err
		end
		socket = nmap.new_socket()
		status, err = socket:connect(host.ip, port.number, port.protocol)
		if (not(status)) then
			return status, string.format("%s connect error: %s", self.program, err)
		else
			self.socket = socket
			self.ip = host.ip
			self.port = port.number
			self.proto = port.protocol
			return status, nil
		end
	end,

	--- Disconnects from the remote program
	--
	-- @return status boolean true on success, false on failure
	-- @return string containing error message (if status is false)
	Disconnect = function(self)
		local status, err = self.socket:close()
		if (not(status)) then
			return status, string.format("%s disconnect error: %s", self.program, err)
		end
		self.socket=nil
		return status, nil
	end,

	--- Checks if the rpc program is supported
	--
	-- @return status boolean true on success, false on failure
	-- @return string containing error message (if status is false)
	ChkProgram = function(self)
		if (not(RPC_version[self.program])) then
			return false, string.format("RPC library does not support: %s protocol", self.program)
		end
		return true, nil
	end,

	--- Checks if the rpc program version is supported
	--
	-- @return status boolean true on success, false on failure
	-- @return string containing error message (if status is false)
	ChkVersion = function(self)
		if ( self.version > RPC_version[self.program].max or self.version < RPC_version[self.program].min ) then
			return false, string.format("RPC library does not support: %s version %d",self.program,self.version)
		end
		return true, nil
	end,

	--- Sets the rpc program version
	--
	-- @return status boolean true
	SetVersion = function(self, version)
		if (RPC_version[self.program] and RPC_args[self.program] and 
		nmap.registry.args and nmap.registry.args[RPC_args[self.program].ver]) then
		self.version = tonumber(nmap.registry.args[RPC_args[self.program].ver])
		elseif (not(self.version) and version) then
			self.version = version
		end
		return true, nil
	end,

	--- Checks if data contains enough bytes to read the <code>needed</code> amount
	--  If it doesn't it attempts to read the remaining amount of bytes from the socket
	--
	-- @param data string containing the current buffer
	-- @param pos number containing the current offset into the buffer
	-- @param needed number containing the number of bytes needed to be available
	-- @return status success or failure
	-- @return data string containing the data passed to the function and the additional data appended to it or error message on failure
	GetAdditionalBytes = function( self, data, pos, needed )

		local status, tmp

		if data:len() - pos + 1 < needed then
			local toread =  needed - ( data:len() - pos + 1 )
			status, tmp = self.socket:receive_bytes( toread )
			if status then
				data = data .. tmp
			else
				return false, string.format("getAdditionalBytes() failed to read: %d bytes from the socket", needed - ( data:len() - pos ) )
			end
		end
		return true, data
	end,

	--- Creates a RPC header
	--
	-- @param xid number
	-- @param procedure number containing the procedure to call
	-- @param auth table containing the authentication data to use
	-- @return status boolean true on success, false on failure
	-- @return string of bytes on success, error message on failure
	CreateHeader = function( self, xid, procedure, auth )
		local RPC_VERSION = 2
		local packet

		if not(xid) then
			xid = math.random(1234567890)
		end
		if not auth then
			return false, "Comm.CreateHeader: No authentication specified"
		elseif auth.type ~= Portmap.AuthType.NULL then
			return false, "Comm.CreateHeader: invalid authentication type specified"
		end

		packet = bin.pack( ">IIIIII", xid, Portmap.MessageType.CALL, RPC_VERSION, self.program_id, self.version, procedure )
		if auth.type == Portmap.AuthType.NULL then
			packet = packet .. bin.pack( "IIII", 0, 0, 0, 0 )
		end		
		return true, packet
	end,

	--- Decodes the RPC header (without the leading 4 bytes as received over TCP)
	--
	-- @param data string containing the buffer of bytes read so far
	-- @param pos number containing the current offset into data
	-- @return pos number containing the offset after the decoding
	-- @return header table containing <code>xid</code>, <code>type</code>, <code>state</code>,
	-- <code>verifier</code> and ( <code>accept_state</code> or <code>denied_state</code> )
	DecodeHeader = function( self, data, pos )
		local header = {}
		local status

		local HEADER_LEN = 20

		header.verifier = {}

		if ( data:len() - pos < HEADER_LEN ) then
			local tmp
			status, tmp = self:GetAdditionalBytes( data, pos, HEADER_LEN - ( data:len() - pos ) )
			if not status then
				stdnse.print_debug(string.format("Comm.ReceivePacket: failed to call GetAdditionalBytes"))
				return -1, nil
			end
			data = data .. tmp
		end

		pos, header.xid, header.type, header.state = bin.unpack(">III", data, pos)

		if ( header.state == Portmap.State.MSG_DENIED ) then
			pos, header.denied_state = bin.unpack(">I", data, pos )
			return pos, header
		end

		pos, header.verifier.flavor = bin.unpack(">I", data, pos)
		pos, header.verifier.length = bin.unpack(">I", data, pos) 

		if header.verifier.length - 8 > 0 then
			status, data = self:GetAdditionalBytes( data, pos, header.verifier.length - 8 )
			if not status then
				stdnse.print_debug(string.format("Comm.ReceivePacket: failed to call GetAdditionalBytes"))
				return -1, nil
			end
			pos, header.verifier.data = bin.unpack("A" .. header.verifier.length - 8, data, pos )
		end
		pos, header.accept_state = bin.unpack(">I", data, pos )


		return pos, header
	end,

	--- Reads the response from the socket
	--
	-- @return status true on success, false on failure
	-- @return data string containing the raw response or error message on failure
	ReceivePacket = function( self )
		local status

		if ( self.proto == "udp" ) then
			-- There's not much we can do in here to check if we received all data
			-- as the packet contains no length field. It's up to each decoding function
			-- to do appropriate checks
			return self.socket:receive_bytes(1)
		else 
			local tmp, lastfragment, length
			local data, pos = "", 1

			repeat
				lastfragment = false
				status, data = self:GetAdditionalBytes( data, pos, 4 )
				if ( not(status) ) then
					return false, "Comm.ReceivePacket: failed to call GetAdditionalBytes"
				end

				pos, tmp = bin.unpack(">i", data, pos )
				length = bit.band( tmp, 0x7FFFFFFF )

				if ( bit.band( tmp, 0x80000000 ) == 0x80000000 ) then
					lastfragment = true
				end

				status, data = self:GetAdditionalBytes( data, pos, length )
				if ( not(status) ) then
					return false, "Comm.ReceivePacket: failed to call GetAdditionalBytes"
				end

				--
				-- When multiple packets are received they look like this
				-- H = Header data
				-- D = Data
				-- 
				-- We don't want the Header
				--
				-- HHHHDDDDDDDDDDDDDDHHHHDDDDDDDDDDD
				-- ^   ^             ^   ^
				-- 1   5             18  22
				--
				-- eg. we want
				-- data:sub(5, 18) and data:sub(22)
				-- 

				local bufcopy = data:sub(pos)

				if 1 ~= pos - 4 then
					bufcopy = data:sub(1, pos - 5) .. bufcopy
					pos = pos - 4
				else
					pos = 1
				end

				pos = pos + length
				data = bufcopy
			until lastfragment == true	
			return true, data
		end
	end,
	
	--- Encodes a RPC packet
	--
	-- @param xid number containing the transaction ID
	-- @param procedure number containing the procedure to call
	-- @param auth table containing authentication information
	-- @param data string containing the packet data
	-- @return packet string containing the encoded packet data
	EncodePacket = function( self, xid, proc, auth, data )
		local status, packet = self:CreateHeader( xid, proc, auth )
		local len
		if ( not(status) ) then
			return
		end
		
		packet = packet .. ( data or "" )
		if ( self.proto == "udp") then
			return packet
		else
			-- set the high bit as this is our last fragment
			len = 0x80000000 + packet:len()
			return bin.pack(">I", len) .. packet 
		end
	end,
	
	SendPacket = function( self, packet )
		return self.socket:send( packet )
	end,

}

--- Portmap (rpcbind) class
Portmap = 
{
	PROTOCOLS = { 
		['tcp'] = 6, 
		['udp'] = 17, 
	},
	
	-- TODO: add more Authentication Protocols
	AuthType =
	{
		NULL = 0
	},	

	-- TODO: complete Authentication stats and error messages
	AuthState =
	{
		AUTH_OK = 0,
		AUTH_BADCRED = 1,
		AUTH_REJECTEDCRED = 2,
		AUTH_BADVERF = 3,
		AUTH_REJECTEDVERF = 4,
		AUTH_TOOWEAK = 5,
		AUTH_INVALIDRESP = 6,
		AUTH_FAILED = 7,
	},

	AuthMsg =
	{
		[0] = "Success.",
		[1] = "bad credential (seal broken).",
		[2] = "client must begin new session.",
		[3] = "bad verifier (seal broken).",
		[4] = "verifier expired or replayed.",
		[5] = "rejected for security reasons.",
		[6] = "bogus response verifier.",
		[7] = "reason unknown.",
	},

	MessageType =
	{
		CALL = 0,
		REPLY = 1
	},

	Procedure =
	{
		[2] = 
		{
			GETPORT = 3,
			DUMP = 4,
		},
	
	},
	
	State =
	{
		MSG_ACCEPTED = 0,
		MSG_DENIED = 1,
	},
	
	AcceptState =
	{
		SUCCESS = 0,
		PROG_UNAVAIL = 1,
		PROG_MISMATCH = 2,
		PROC_UNAVAIL = 3,
		GARBAGE_ARGS = 4,
		SYSTEM_ERR = 5,
	},

	AcceptMsg =
	{
		[0] = "RPC executed successfully.",
		[1] = "remote hasn't exported program.",
		[2] = "remote can't support version.",
		[3] = "program can't support procedure.",
		[4] = "procedure can't decode params.",
		[5] = "errors like memory allocation failure.",
	},

	RejectState =
	{
		RPC_MISMATCH = 0,
		AUTH_ERROR = 1, 
	},

	RejectMsg =
	{
		[0] = "RPC version number != 2.",
		[1] = "remote can't authenticate caller.",
	},

        new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
	end,
		
	--- Dumps a list of RCP programs from the portmapper
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @return status boolean true on success, false on failure
	-- @return result table containing RPC program information or error message
	--         on failure. The table has the following format:
	--
	-- <code>
	-- table[program_id][protocol]["port"] = <port number>
	-- table[program_id][protocol]["version"] = <table of versions>
	-- </code>
	--
	-- Where
	--  o program_id is the number associated with the program
	--  o protocol is either "tcp" or "udp"
	--
	Dump = function(self, comm)
		local status, data, packet, response, pos, header
		local program_table = setmetatable({}, { __mode = 'v' })

		if nmap.registry[comm.ip] == nil then
			nmap.registry[comm.ip] = {}
		end
		if nmap.registry[comm.ip]['portmap'] == nil then
			nmap.registry[comm.ip]['portmap'] = {}
		elseif next(nmap.registry[comm.ip]['portmap']) ~= nil then
			return true, nmap.registry[comm.ip]['portmap']
		end

		packet = comm:EncodePacket( nil, Portmap.Procedure[comm.version].DUMP, { type=Portmap.AuthType.NULL }, data )
		if (not(comm:SendPacket(packet))) then
			return false, "Portmap.Dump: Failed to send data"
		end
		status, data = comm:ReceivePacket()
		if ( not(status) ) then
			return false, "Portmap.Dump: Failed to read data from socket"
		end

		pos, header = comm:DecodeHeader( data, 1 )
		if ( not(header) ) then
			return false, "Portmap.Dump: Failed to decode RPC header"
		end

		if header.type ~= Portmap.MessageType.REPLY then
			return false, "Portmap.Dump: Packet was not a reply"
		end

		if header.state ~= Portmap.State.MSG_ACCEPTED then
			if (Portmap.RejectMsg[header.denied_state]) then
				return false, string.format("Portmap.Dump: RPC call failed: %s",
							Portmap.RejectMsg[header.denied_state])
			else
				return false, string.format("Portmap.Dump: RPC call failed: code %d",
							header.state)
			end
		end

		if header.accept_state ~= Portmap.AcceptState.SUCCESS then
			if (Portmap.AcceptMsg[header.accept_state]) then
				return false, string.format("Portmap.Dump: RPC accepted state: %s",
							Portmap.AcceptMsg[header.accept_state])
			else
				return false, string.format("Portmap.Dump: RPC accepted state code %d",
							header.accept_state)
			end
		end

		while true do
			local vfollows
			local program, version, protocol, port

			status, data = comm:GetAdditionalBytes( data, pos, 4 )
			if ( not(status) ) then
				return false, "Portmap.Dump: Failed to call GetAdditionalBytes"
			end
			pos, vfollows = bin.unpack( ">I", data, pos )		
			if ( vfollows == 0 ) then
				break
			end
			
			pos, program, version, protocol, port = bin.unpack(">IIII", data, pos)
			if ( protocol == Portmap.PROTOCOLS.tcp ) then
				protocol = "tcp"
			elseif ( protocol == Portmap.PROTOCOLS.udp ) then
				protocol = "udp"
			end
						
			program_table[program] = program_table[program] or {}
			program_table[program][protocol] = program_table[program][protocol] or {}
			program_table[program][protocol]["port"] = port
			program_table[program][protocol]["version"] = program_table[program][protocol]["version"] or {}
			table.insert( program_table[program][protocol]["version"], version )
			-- parts of the code rely on versions being in order
			-- this way the highest version can be chosen by choosing the last element
			table.sort( program_table[program][protocol]["version"] )
		end

		nmap.registry[comm.ip]['portmap'] = program_table
		return true, nmap.registry[comm.ip]['portmap']  	
	end,
	
	--- Queries the portmapper for the port of the selected program, 
	--  protocol and version
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @param program string name of the program
	-- @param protocol string containing either "tcp" or "udp"
	-- @param version number containing the version of the queried program
	-- @return number containing the port number
	GetPort = function( self, comm, program, protocol, version )
		local status, data, response, header, pos, packet
		local xid
		
		if ( not( Portmap.PROTOCOLS[protocol] ) ) then
			return false, ("Portmap.GetPort: Protocol %s not supported"):format(protocol)
		end
		
		if ( Util.ProgNameToNumber(program) == nil ) then
			return false, ("Portmap.GetPort: Unknown program name: %s"):format(program)
		end
						
		data = bin.pack( ">I>I>I>I", Util.ProgNameToNumber(program), version, Portmap.PROTOCOLS[protocol], 0 )
		packet = comm:EncodePacket( xid, Portmap.Procedure[comm.version].GETPORT, { type=Portmap.AuthType.NULL }, data )
		
		if (not(comm:SendPacket(packet))) then
			return false, "Portmap.GetPort: Failed to send data"
		end

		data = ""
		status, data = comm:ReceivePacket()
		if ( not(status) ) then
			return false, "Portmap.GetPort: Failed to read data from socket"
		end

		pos, header = comm:DecodeHeader( data, 1 )
		
		if ( not(header) ) then
			return false, "Portmap.GetPort: Failed to decode RPC header"
		end

		if header.type ~= Portmap.MessageType.REPLY then
			return false, "Portmap.GetPort: Packet was not a reply"
		end

		if header.state ~= Portmap.State.MSG_ACCEPTED then
			if (Portmap.RejectMsg[header.denied_state]) then
				return false, string.format("Portmap.GetPort: RPC call failed: %s",
							Portmap.RejectMsg[header.denied_state])
			else
				return false, string.format("Portmap.GetPort: RPC call failed: code %d",
							header.state)
			end
		end

		if header.accept_state ~= Portmap.AcceptState.SUCCESS then
			if (Portmap.AcceptMsg[header.accept_state]) then
				return false, string.format("Portmap.GetPort: RPC accepted state: %s",
							Portmap.AcceptMsg[header.accept_state])
			else
				return false, string.format("Portmap.GetPort: RPC accepted state code %d",
							header.accept_state)
			end
		end

		status, data = comm:GetAdditionalBytes( data, pos, 4 )
		if ( not(status) ) then
			return false, "Portmap.GetPort: Failed to call GetAdditionalBytes"
		end

		return true, select(2, bin.unpack(">I", data, pos ) )	
	end,

}

--- Mount class handling communication with the mountd program
--
-- Currently supports versions 1 through 3
-- Can be called either directly or through the static Helper class
--
Mount = {

	StatMsg = {
		[1] = "Not owner.",
		[2] = "No such file or directory.",
		[5] = "I/O error.",
		[13] = "Permission denied.",
		[20] = "Not a directory.",
		[22] = "Invalid argument.",
		[63] = "Filename too long.",
		[10004] = "Operation not supported.",
		[10006] = "A failure on the server.",
	},

	StatCode = {
		MNT_OK = 0,
		MNTERR_PERM = 1,
		MNTERR_NOENT = 2,
		MNTERR_IO = 5,
		MNTERR_ACCES = 13,
		MNTERR_NOTDIR = 20,
		MNTERR_INVAL = 22,
		MNTERR_NAMETOOLONG = 63,
		MNTERR_NOTSUPP = 10004,
		MNTERR_SERVERFAULT = 10006,	
	},

	Procedure = 
	{
		MOUNT = 1,
		DUMP = 2,
		UMNT = 3,
		UMNTALL = 4,
		EXPORT = 5,
	},

	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
	end,
		
	--- Requests a list of NFS export from the remote server
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @return status success or failure
	-- @return entries table containing a list of share names (strings)
	Export = function(self, comm)

		local msg_type = 0
		local packet
		local pos = 1
		local header = {}
		local entries = {}
		local data = ""
		local status

		if comm.proto ~= "tcp" and comm.proto ~= "udp" then
			return false, "Mount.Export: Protocol should be either udp or tcp"
		end
		packet = comm:EncodePacket(nil, Mount.Procedure.EXPORT, { type=Portmap.AuthType.NULL }, nil )
		if (not(comm:SendPacket( packet ))) then
			return false, "Mount.Export: Failed to send data"
		end

		status, data = comm:ReceivePacket()
		if ( not(status) ) then
			return false, "Mount.Export: Failed to read data from socket"
		end

		-- make sure we have atleast 24 bytes to unpack the header
		status, data = comm:GetAdditionalBytes( data, pos, 24 )
		if (not(status)) then
			return false, "Mount.Export: Failed to call GetAdditionalBytes"
		end
		pos, header = comm:DecodeHeader( data, pos )
		if not header then
			return false, "Mount.Export: Failed to decode header"
		end

		if header.type ~= Portmap.MessageType.REPLY then
			return false, "Mount.Export: packet was not a reply"
		end

		if header.state ~= Portmap.State.MSG_ACCEPTED then
			if (Portmap.RejectMsg[header.denied_state]) then
				return false, string.format("Mount.Export: RPC call failed: %s",
							Portmap.RejectMsg[header.denied_state])
			else
				return false, string.format("Mount.Export: RPC call failed: code %d", header.state)
			end
		end

		if header.accept_state ~= Portmap.AcceptState.SUCCESS then
			if (Portmap.AcceptMsg[header.accept_state]) then
				return false, string.format("Mount.Export: RPC accepted state: %s",
							Portmap.AcceptMsg[header.accept_state])
			else
				return false, string.format("Mount.Export: RPC accepted state code %d",
							header.accept_state)
			end
		end

		---
		--  Decode directory entries
		--
		--  [entry]
		--     4 bytes   - value follows (1 if more data, 0 if not)
		--     [Directory]
		--  	  4 bytes   - value len
		--  	  len bytes - directory name
		--  	  ? bytes   - fill bytes (@see calcFillByte)
		--     [Groups]
		--		   4 bytes  - value follows (1 if more data, 0 if not)
		--         [Group] (1 or more)
		--            4 bytes   - group len
		--			  len bytes - group value	
		-- 	          ? bytes   - fill bytes (@see calcFillByte)		  
		---
		while true do
			-- make sure we have atleast 4 more bytes to check for value follows
			status, data = comm:GetAdditionalBytes( data, pos, 4 )
			if (not(status)) then
				return false, "Mount.Export: Failed to call GetAdditionalBytes"
			end

			local data_follows
			pos, data_follows = bin.unpack( ">I", data, pos )

			if data_follows ~= 1 then
				break
			end

			--- Export list entry starts here
			local entry = {}
			local len	

			-- make sure we have atleast 4 more bytes to get the length
			status, data = comm:GetAdditionalBytes( data, pos, 4 )
			if (not(status)) then
				return false, "Mount.Export: Failed to call GetAdditionalBytes"
			end
			pos, len = bin.unpack(">I", data, pos )

			status, data = comm:GetAdditionalBytes( data, pos, len )
			if (not(status)) then
				return false, "Mount.Export: Failed to call GetAdditionalBytes"
			end
			pos, entry.name = bin.unpack("A" .. len, data, pos )
			pos = pos + Util.CalcFillBytes( len )

			-- decode groups
			while true do
				local group 

				status, data = comm:GetAdditionalBytes( data, pos, 4 )
				if (not(status)) then
					return false, "Mount.Export: Failed to call GetAdditionalBytes"
				end
				pos, data_follows = bin.unpack( ">I", data, pos )

				if data_follows ~= 1 then
					break
				end

				status, data = comm:GetAdditionalBytes( data, pos, 4 )
				if (not(status)) then
					return false, "Mount.Export: Failed to call GetAdditionalBytes"
				end
				pos, len = bin.unpack( ">I", data, pos )
				status, data = comm:GetAdditionalBytes( data, pos, len )
				if (not(status)) then
					return false, "Mount.Export: Failed to call GetAdditionalBytes"
				end
				pos, group = bin.unpack( "A" .. len, data, pos )

				table.insert( entry, group )
				pos = pos + Util.CalcFillBytes( len )
			end		
			table.insert(entries, entry)
		end
		return true, entries
	end,

	--- Attempts to mount a remote export in order to get the filehandle
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @param path string containing the path to mount
	-- @return status success or failure
	-- @return fhandle string containing the filehandle of the remote export
	Mount = function(self, comm, path)
		local packet, mount_status
		local _, pos, data, header, fhandle = "", 1, "", "", {}
		local status, len

		data = bin.pack(">IA", path:len(), path)

		for i=1, Util.CalcFillBytes( path:len() ) do
			data = data .. string.char( 0x00 )
		end

		packet = comm:EncodePacket( nil, Mount.Procedure.MOUNT, { type=Portmap.AuthType.NULL }, data )
		if (not(comm:SendPacket(packet))) then
			return false, "Mount: Failed to send data"
		end

		status, data = comm:ReceivePacket()
		if ( not(status) ) then
			return false, "Mount: Failed to read data from socket"
		end

		pos, header = comm:DecodeHeader( data, pos )
		if not header then
			return false, "Mount: Failed to decode header"
		end

		if header.type ~= Portmap.MessageType.REPLY then
			return false, "Mount: Packet was not a reply"
		end

		if header.state ~= Portmap.State.MSG_ACCEPTED then
			if (Portmap.RejectMsg[header.denied_state]) then
				return false, string.format("Mount: RPC call failed: %s",
							Portmap.RejectMsg[header.denied_state])
			else
				return false, string.format("Mount: RPC call failed: code %d",
							header.state)
			end
		end

		if header.accept_state ~= Portmap.AcceptState.SUCCESS then
			if (Portmap.AcceptMsg[header.accept_state]) then
				return false, string.format("Mount (%s): RPC accepted state: %s",
							path, Portmap.AcceptMsg[header.accept_state])
			else
				return false, string.format("Mount (%s): RPC accepted state code %d",
							path, header.accept_state)
			end
		end

		status, data = comm:GetAdditionalBytes( data, pos, 4 )
		if (not(status)) then
			return false, "Mount: Failed to call GetAdditionalBytes"
		end
		pos, mount_status = bin.unpack(">I", data, pos )

		if (mount_status ~= Mount.StatCode.MNT_OK) then
			if (Mount.StatMsg[mount_status]) then
				return false, string.format("Mount failed: %s",Mount.StatMsg[mount_status])
			else
				return false, string.format("Mount failed: code %d", mount_status)
			end
		end

		if ( comm.version == 3 ) then
			status, data = comm:GetAdditionalBytes( data, pos, 4 )
			if (not(status)) then
				return false, "Mount: Failed to call GetAdditionalBytes"
			end
			_, len = bin.unpack(">I", data, pos )
			status, data = comm:GetAdditionalBytes( data, pos, len + 4 )
			if (not(status)) then
				return false, "Mount: Failed to call GetAdditionalBytes"
			end
			pos, fhandle = bin.unpack( "A" .. len + 4, data, pos )
		elseif ( comm.version < 3 ) then
			status, data = comm:GetAdditionalBytes( data, pos, 32 )
			if (not(status)) then
				return false, "Mount: Failed to call GetAdditionalBytes"
			end
			pos, fhandle = bin.unpack( "A32", data, pos )
		else
			return false, "Mount failed"
		end

		return true, fhandle
	end,

	--- Attempts to unmount a remote export in order to get the filehandle
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @param path string containing the path to mount
	-- @return status success or failure
	-- @return error string containing error if status is false
	Unmount = function(self, comm, path)
		local packet, status
		local _, pos, data, header, fhandle = "", 1, "", "", {}

		data = bin.pack(">IA", path:len(), path)

		for i=1, Util.CalcFillBytes( path:len() ) do
			data = data .. string.char( 0x00 )
		end

		packet = comm:EncodePacket( nil, Mount.Procedure.UMNT, { type=Portmap.AuthType.NULL }, data )
		if (not(comm:SendPacket(packet))) then
			return false, "Unmount: Failed to send data"
		end

		status, data = comm:ReceivePacket( )
		if ( not(status) ) then
			return false, "Unmount: Failed to read data from socket"
		end

		pos, header = comm:DecodeHeader( data, pos )
		if not header then
			return false, "Unmount: Failed to decode header"
		end

		if header.type ~= Portmap.MessageType.REPLY then
			return false, "Unmount: Packet was not a reply"
		end

		if header.state ~= Portmap.State.MSG_ACCEPTED then
			if (Portmap.RejectMsg[header.denied_state]) then
				return false, string.format("Unmount: RPC call failed: %s",
							Portmap.RejectMsg[header.denied_state])
			else
				return false, string.format("Unmount: RPC call failed: code %d",
							header.state)
			end
		end

		if header.accept_state ~= Portmap.AcceptState.SUCCESS then
			if (Portmap.AcceptMsg[header.accept_state]) then
				return false, string.format("Unmount (%s): RPC accepted state: %s",
							path, Portmap.AcceptMsg[header.accept_state])
			else
				return false, string.format("Unmount (%s): RPC accepted state code %d",
							path, header.accept_state)
			end
		end

		return true, ""
	end,

}

--- NFS class handling communication with the nfsd program
--
-- Currently supports versions 1 through 3
-- Can be called either directly or through the static Helper class
--
NFS = {

	-- NFS error msg v2 and v3
	StatMsg = {
		[1] = "Not owner.",
		[2] = "No such file or directory.",
		[5] = "I/O error.",
		[6] = "I/O error. No such device or address.",
		[13] = "Permission denied.",
		[17] = "File exists.",
		[18] = "Attempt to do a cross-device hard link.",
		[19] = "No such device.",
		[20] = "Not a directory.",
		[21] = "Is a directory.",
		[22] = "Invalid argument or unsupported argument for an operation.",
		[27] = "File too large.",
		[28] = "No space left on device.",
		[30] = "Read-only file system.",
		[31] = "Too many hard links.",
		[63] = "The filename in an operation was too long.",
		[66] = "An attempt was made to remove a directory that was not empty.",
		[69] = "Resource (quota) hard limit exceeded.",
		[70] = "Invalid file handle.",
		[71] = "Too many levels of remote in path.",
		[99] = "The server's write cache used in the \"WRITECACHE\" call got flushed to disk.",
		[10001] = "Illegal NFS file handle.",
		[10002] = "Update synchronization mismatch was detected during a SETATTR operation.",
		[10003] = "READDIR or READDIRPLUS cookie is stale.",
		[10004] = "Operation is not supported.",
		[10005] = "Buffer or request is too small.",
		[10006] = "An error occurred on the server which does not map to any of the legal NFS version 3 protocol error values.",
		[10007] = "An attempt was made to create an object of a type not supported by the server.",
		[10008] = "The server initiated the request, but was not able to complete it in a timely fashion.",
	},

	StatCode = {
		-- NFS Version 1
		[1] = {
			NFS_OK		= 0,
			NFSERR_PERM	= 1,
			NFSERR_NOENT	= 2,
			NFSERR_IO	= 5,
			NFSERR_NXIO	= 6,
			NFSERR_ACCES	= 13,
			NFSERR_EXIST	= 17,
			NFSERR_NODEV	= 19,
			NFSERR_NOTDIR	= 20,
			NFSERR_ISDIR	= 21,
			NFSERR_FBIG	= 27,
			NFSERR_NOSPC	= 28,
			NFSERR_ROFS	= 30,
			NFSERR_NAMETOOLONG = 63,
			NFSERR_NOTEMPTY	= 66,
			NFSERR_DQUOT	= 69,
			NFSERR_STALE	= 70,
			NFSERR_WFLUSH	= 99,
		},

		-- NFS Version 2
		[2] = {
			NFS_OK		= 0,
			NFSERR_PERM	= 1,
			NFSERR_NOENT	= 2,
			NFSERR_IO	= 5,
			NFSERR_NXIO	= 6,
			NFSERR_ACCES	= 13,
			NFSERR_EXIST	= 17,
			NFSERR_NODEV	= 19,
			NFSERR_NOTDIR	= 20,
			NFSERR_ISDIR	= 21,
			NFSERR_FBIG	= 27,
			NFSERR_NOSPC	= 28,
			NFSERR_ROFS	= 30,
			NFSERR_NAMETOOLONG = 63,
			NFSERR_NOTEMPTY	= 66,
			NFSERR_DQUOT	= 69,
			NFSERR_STALE	= 70,
			NFSERR_WFLUSH	= 99,
		},

		-- NFS Version 3
		[3] = {
			NFS_OK		= 0,
			NFSERR_PERM	= 1,
			NFSERR_NOENT	= 2,
			NFSERR_IO	= 5,
			NFSERR_NXIO	= 6,
			NFSERR_ACCES	= 13,
			NFSERR_EXIST	= 17,
			NFSERR_XDEV	= 18,
			NFSERR_NODEV	= 19,
			NFSERR_NOTDIR	= 20,
			NFSERR_ISDIR	= 21,
			NFSERR_INVAL	= 22,
			NFSERR_FBIG	= 27,
			NFSERR_NOSPC	= 28,
			NFSERR_ROFS	= 30,
			NFSERR_MLINK	= 31,
			NFSERR_NAMETOOLONG = 63,
			NFSERR_NOTEMPTY = 66,
			NFSERR_DQUOT	= 69,
			NFSERR_STALE	= 70,
			NFSERR_REMOTE	= 71,
			NFSERR_BADHANDLE = 10001,
			NFSERR_NOT_SYNC = 10002,
			NFSERR_BAD_COOKIE = 10003,
			NFSERR_NOTSUPP = 10004,
			NFSERR_TOOSMALL = 10005,
			NFSERR_SERVERFAULT = 10006,
			NFSERR_BADTYPE = 10007,
			NFSERR_JUKEBOX = 10008,
		},
	},

	-- Unfortunately the NFS procedure numbers differ in between versions
	Procedure = 
	{
		-- NFS Version 1
		[1] =
		{
			GETATTR = 1,
			ROOT = 3,
			LOOKUP = 4,
			EXPORT = 5,
			READDIR = 16,
			STATFS = 17,
		},

		-- NFS Version 2
		[2] = 
		{
			GETATTR = 1,
			ROOT = 3,
			LOOKUP = 4,
			EXPORT = 5,
			READDIR = 16,
			STATFS = 17,
		},

		-- NFS Version 3
		[3] = 
		{
			GETATTR = 1,
			SETATTR = 2,
			LOOKUP = 3,
			ACCESS = 4,
			EXPORT = 5,
			READDIR = 16,
			READDIRPLUS = 17,
			FSSTAT = 18,
			FSINFO = 19,
			PATHCONF = 20,
			COMMIT = 21,
		},
	},

	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
    	end,

    	--- Decodes the READDIR section of a NFS ReadDir response
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @param data string containing the buffer of bytes read so far
	-- @param pos number containing the current offset into data
	-- @return pos number containing the offset after the decoding
	-- @return entries table containing two table entries <code>attributes</code>
	--         and <code>entries</code>. The attributes entry is only present when
	--         using NFS version 3. The <code>entries</code> field contain one
	--         table for each file/directory entry. It has the following fields
	--         <code>file_id</code>, <code>name</code> and <code>cookie</code>
	--
	ReadDirDecode = function( self, comm, data, pos )
		local entry, response = {}, {}
		local value_follows
		local status, _

		status, data = comm:GetAdditionalBytes( data, pos, 4 )
		if (not(status)) then
			stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
			return -1, nil
		end
		
		pos, status = bin.unpack(">I", data, pos)
		if (status ~= NFS.StatCode[comm.version].NFS_OK) then
			if (NFS.StatMsg[status]) then
				stdnse.print_debug(string.format("READDIR query failed: %s", NFS.StatMsg[status])) 
			else
				stdnse.print_debug(string.format("READDIR query failed: code %d", status))
			end
			return -1, nil
		end

		if ( 3 == comm.version ) then
			local attrib = {}
			response.attributes = {}
			status, data = comm:GetAdditionalBytes( data, pos, 4 )
			if (not(status)) then
				stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
				return -1, nil
			end

			pos, value_follows = bin.unpack(">I", data, pos)
			if value_follows == 0 then
				return -1, nil
			end
			status, data = comm:GetAdditionalBytes( data, pos, 84 )
			if (not(status)) then
				stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
				return -1, nil
			end
			pos, attrib = Util.unmarshall_nfsattr(data, pos, comm.version)
			table.insert(response.attributes, attrib)
			-- opaque data
			status, data = comm:GetAdditionalBytes( data, pos, 8 )
			if (not(status)) then
				stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
				return -1, nil
			end
			pos, _ = bin.unpack(">L", data, pos)
		end

		response.entries = {}
		while true do
			entry = {}
			status, data = comm:GetAdditionalBytes( data, pos, 4 )
			if (not(status)) then
				stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
				return -1, nil
			end
	
			pos, value_follows = bin.unpack(">I", data, pos)

			if ( value_follows == 0 ) then
				break
			end

			if ( 3 == comm.version ) then
				status, data = comm:GetAdditionalBytes( data, pos, 8 )
				if (not(status)) then
					stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
					return -1, nil
				end
				pos, entry.fileid = bin.unpack(">L", data, pos )
			else
				status, data = comm:GetAdditionalBytes( data, pos, 4 )
				if (not(status)) then
					stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
					return -1, nil
				end
				pos, entry.fileid = bin.unpack(">I", data, pos )
			end

			status, data = comm:GetAdditionalBytes( data, pos, 4 )
			if (not(status)) then
				stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
				return -1, nil
			end
			
			pos, entry.length = bin.unpack(">I", data, pos)
			status, data = comm:GetAdditionalBytes( data, pos, entry.length )
			if (not(status)) then
				stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
				return -1, nil
			end
			
			pos, entry.name = bin.unpack("A" .. entry.length, data, pos)
			pos = pos + Util.CalcFillBytes( entry.length )

			if ( 3 == comm.version ) then
				status, data = comm:GetAdditionalBytes( data, pos, 8 )
				if (not(status)) then
					stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
					return -1, nil
				end
				pos, entry.cookie = bin.unpack(">L", data, pos)
			else
				status, data = comm:GetAdditionalBytes(  data, pos, 4 )
				if (not(status)) then
					stdnse.print_debug("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
					return -1, nil
				end
				pos, entry.cookie = bin.unpack(">I", data, pos)
			end
			table.insert( response.entries, entry )
		end
		return pos, response	
	end,
	
	--- Reads the contents inside a NFS directory
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @param file_handle string containing the filehandle to query
	-- @return status true on success, false on failure
	-- @return table of file table entries as described in <code>decodeReadDir</code>
	ReadDir = function( self, comm, file_handle )

		local status, packet
		local cookie, count = 0, 8192
		local pos, data, _ = 1, "", ""
		local header, response = {}, {}

		if ( not(file_handle) ) then
			return false, "ReadDir: No filehandle received"
		end

		if ( comm.version == 3 ) then
			local opaque_data = 0
			data = bin.pack("A>L>L>I", file_handle, cookie, opaque_data, count)	
		else
			data = bin.pack("A>I>I", file_handle, cookie, count)
		end		
		packet = comm:EncodePacket( nil, NFS.Procedure[comm.version].READDIR, { type=Portmap.AuthType.NULL }, data )
		if(not(comm:SendPacket( packet ))) then
			return false, "ReadDir: Failed to send data"
		end

		status, data = comm:ReceivePacket()
		if ( not(status) ) then
			return false, "ReadDir: Failed to read data from socket"
		end

		pos, header = comm:DecodeHeader( data, pos )
		if not header then
			return false, "ReadDir: Failed to decode header"
		end
		pos, response = self:ReadDirDecode( comm, data, pos )
		if (not(response)) then
			return false, "ReadDir: Failed to decode the READDIR section"
		end
		return true, response
	end,

        ReadDirPlusDecode =  function(self, comm, data, pos)
          local response, status, value_follows, _ = {}

	  status, data = comm:GetAdditionalBytes(data, pos, 4)
          if not status then
            stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
            return -1, nil
          end

          pos, status = bin.unpack(">I", data, pos)
	  if (status ~= NFS.StatCode[comm.version].NFS_OK) then
	    if (NFS.StatMsg[status]) then
	      stdnse.print_debug(string.format("READDIRPLUS query failed: %s", NFS.StatMsg[status])) 
	    else
	      stdnse.print_debug(string.format("READDIRPLUS query failed: code %d", status))
	    end
	    return -1, nil
	  end
          
	  status, data = comm:GetAdditionalBytes(data, pos, 4)
	  if not status then
	    stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	    return -1, nil
	  end

          pos, value_follows = bin.unpack(">I", data, pos)
          if value_follows == 0 then
	    stdnse.print_debug("NFS.ReadDirPlusDecode: Attributes follow failed")
            return -1, nil
          end

	  status, data = comm:GetAdditionalBytes( data, pos, 84 )
	  if not status then
	    stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	    return -1, nil
	  end

          response.attributes = {}
	  pos, response.attributes = Util.unmarshall_nfsattr(data, pos,
	                                                     comm.version)

	  status, data = comm:GetAdditionalBytes(data, pos, 8)
	  if not status then
	    stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	    return -1, nil
	  end
	  pos, _ = bin.unpack(">L", data, pos)

          response.entries = {}

          while true do
            local entry, len = {}
            status, data = comm:GetAdditionalBytes(data, pos, 4)
	    if not status then
	      stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	      return -1, nil
	    end
	
	    pos, value_follows = bin.unpack(">I", data, pos)

	    if (value_follows == 0) then
		break
	    end
	    status, data = comm:GetAdditionalBytes(data, pos, 8)
	    if not status then
	      stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	      return -1, nil
	    end
	    pos, entry.fileid = bin.unpack(">L", data, pos)

	    status, data = comm:GetAdditionalBytes(data, pos, 4)

	    if not status then
	      stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	      return -1, nil
	    end

	    pos, entry.length = bin.unpack(">I", data, pos)
	    status, data = comm:GetAdditionalBytes( data, pos, entry.length )
	    if not status then
	      stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	      return -1, nil
	    end
			
	    pos, entry.name = bin.unpack("A" .. entry.length, data, pos)
	    pos = pos + Util.CalcFillBytes(entry.length)
	    status, data = comm:GetAdditionalBytes(data, pos, 8)
	    if not status then
	      stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	      return -1, nil
	    end
	    pos, entry.cookie = bin.unpack(">L", data, pos)
            status, data = comm:GetAdditionalBytes(data, pos, 4)
	    if not status then
	      stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	      return -1, nil
	    end

            entry.attributes = {}
	    pos, value_follows = bin.unpack(">I", data, pos)
	    if (value_follows ~= 0) then
	      pos, entry.attributes = Util.unmarshall_nfsattr(data, pos, comm.version)
            else
	      stdnse.print_debug(4, "NFS.ReadDirPlusDecode: %s Attributes follow failed",
	                         entry.name)
	    end

            status, data = comm:GetAdditionalBytes(data, pos, 4)
	    if not status then
	      stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	      return -1, nil
	    end

            entry.fhandle = ""
	    pos, value_follows = bin.unpack(">I", data, pos)
	    if (value_follows ~= 0) then
	      status, data = comm:GetAdditionalBytes(data, pos, 4)
	      if not status then
	        stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	        return -1, nil
	      end
	    
	      _, len = bin.unpack(">I", data, pos)
	      status, data = comm:GetAdditionalBytes(data, pos, len + 4)
	      if not status then
	        stdnse.print_debug("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
	        return -1, nil
	      end
	      pos, entry.fhandle = bin.unpack( "A" .. len + 4, data, pos )
	    else
	      stdnse.print_debug(4, "NFS.ReadDirPlusDecode: %s handle follow failed",
	                         entry.name)
	    end
            
            table.insert(response.entries, entry)
	  end

          return pos, response
        end,

        ReadDirPlus = function(self, comm, file_handle)
          local status, packet
          local cookie, opaque_data, dircount, maxcount = 0, 0, 512, 8192
          local pos, data = 1, ""
          local header, response = {}, {}

          if (comm.version < 3) then
            return false, string.format("NFS version: %d does not support ReadDirPlus",
                                        comm.version)
          end

          if not file_handle then
            return false, "ReadDirPlus: No filehandle received"
          end 

          data = bin.pack("A>L>L>I>I", file_handle, cookie,
                          opaque_data, dircount, maxcount)

          packet = comm:EncodePacket(nil, NFS.Procedure[comm.version].READDIRPLUS,
                                    {type = Portmap.AuthType.NULL }, data)

          if (not(comm:SendPacket(packet))) then
            return false, "ReadDirPlus: Failed to send data"
          end

          status, data = comm:ReceivePacket()
          if not status then
	    return false, "ReadDirPlus: Failed to read data from socket"
          end

	  pos, header = comm:DecodeHeader( data, pos )
	  if not header then
	    return false, "ReadDirPlus: Failed to decode header"
	  end
	  pos, response = self:ReadDirPlusDecode( comm, data, pos )
	  if not response then
	    return false, "ReadDirPlus: Failed to decode the READDIR section"
	  end

	  return true, response
        end,

	--- Gets filesystem stats (Total Blocks, Free Blocks and Available block) on a remote NFS share
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @param file_handle string containing the filehandle to query
	-- @return status true on success, false on failure
	-- @return statfs table with the fields <code>transfer_size</code>, <code>block_size</code>, 
	-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
	-- @return errormsg if status is false
	StatFs = function( self, comm, file_handle )

		local status, packet
		local pos, data, _ = 1, "", ""
		local header, statfs = {}, {}

		if ( comm.version > 2 ) then
			return false, ("StatFs: Version %d not supported"):format(comm.version)
		end

		if ( not(file_handle) or file_handle:len() ~= 32 ) then
			return false, "StatFs: Incorrect filehandle received"
		end

		data = bin.pack("A", file_handle )
		packet = comm:EncodePacket( nil, NFS.Procedure[comm.version].STATFS, { type=Portmap.AuthType.NULL }, data )
		if (not(comm:SendPacket( packet ))) then
			return false, "StatFS: Failed to send data"
		end

		status, data = comm:ReceivePacket( )
		if ( not(status) ) then
			return false, "StatFs: Failed to read data from socket"
		end

		pos, header = comm:DecodeHeader( data, pos )

		if not header then
			return false, "StatFs: Failed to decode header"
		end

		pos, statfs = self:StatFsDecode( comm, data, pos )

		if not statfs then
			return false, "StatFs: Failed to decode statfs structure"
		end
		return true, statfs
	end,

	--- Attempts to decode the attributes section of the reply
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @param data string containing the full statfs reply
	-- @param pos number pointing to the statfs section of the reply
	-- @return pos number containing the offset after decoding
	-- @return statfs table with the following fields: <code>type</code>, <code>mode</code>, 
	-- 	<code>nlink</code>, <code>uid</code>, <code>gid</code>, <code>size</code>,
	--  <code>blocksize</code>, <code>rdev</code>, <code>blocks</code>, <code>fsid</code>,
	--  <code>fileid</code>, <code>atime</code>, <code>mtime</code> and <code>ctime</code>
	--
	GetAttrDecode = function( self, comm, data, pos )
		local status

		status, data = comm:GetAdditionalBytes( data, pos, 4 )
		if (not(status)) then
			stdnse.print_debug("GetAttrDecode: Failed to call GetAdditionalBytes")
			return -1, nil
		end
		pos, status = bin.unpack(">I", data, pos)

		if (status ~= NFS.StatCode[comm.version].NFS_OK) then
			if (NFS.StatMsg[status]) then
				stdnse.print_debug(string.format("GETATTR query failed: %s", NFS.StatMsg[status])) 
			else
				stdnse.print_debug(string.format("GETATTR query failed: code %d", status))
			end
			return -1, nil
		end

		if ( comm.version < 3 ) then
			status, data = comm:GetAdditionalBytes( data, pos, 64 )
		elseif (comm.version == 3) then
			status, data = comm:GetAdditionalBytes( data, pos, 84 )
		else
			stdnse.print_debug("GetAttrDecode: Unsupported version")
			return -1, nil
		end
		if ( not(status) ) then
			stdnse.print_debug("GetAttrDecode: Failed to call GetAdditionalBytes")
			return -1, nil
		end
		return Util.unmarshall_nfsattr(data, pos, comm.version)
	end,

	--- Gets mount attributes (uid, gid, mode, etc ..) from a remote NFS share
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @param file_handle string containing the filehandle to query
	-- @return status true on success, false on failure
	-- @return attribs table with the fields <code>type</code>, <code>mode</code>, 
	-- 	<code>nlink</code>, <code>uid</code>, <code>gid</code>, <code>size</code>,
	--  <code>blocksize</code>, <code>rdev</code>, <code>blocks</code>, <code>fsid</code>,
	--  <code>fileid</code>, <code>atime</code>, <code>mtime</code> and <code>ctime</code>
	-- @return errormsg if status is false
	GetAttr = function( self, comm, file_handle )
		local data, packet, status, attribs, pos, header

		data = bin.pack("A", file_handle)
		packet = comm:EncodePacket( nil, NFS.Procedure[comm.version].GETATTR, { type=Portmap.AuthType.NULL }, data )
		if(not(comm:SendPacket(packet))) then
			return false, "GetAttr: Failed to send data"
		end

		status, data = comm:ReceivePacket()
		if ( not(status) ) then
			return false, "GetAttr: Failed to read data from socket"
		end

		pos, header = comm:DecodeHeader( data, 1 )
		if not header then
			return false, "GetAttr: Failed to decode header"
		end

		pos, attribs = self:GetAttrDecode(comm, data, pos )
		if not attribs then
			return false, "GetAttr: Failed to decode attrib structure"
		end

		return true, attribs
	end,

	--- Attempts to decode the StatFS section of the reply
	--
	-- @param Comm object handles rpc program information and
	-- 	low-level packet manipulation
	-- @param data string containing the full statfs reply
	-- @param pos number pointing to the statfs section of the reply
	-- @return pos number containing the offset after decoding
	-- @return statfs table with the following fields: <code>transfer_size</code>, <code>block_size</code>, 
	-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
	StatFsDecode = function( self, comm, data, pos )
		local status
		local statfs = {}

		status, data = comm:GetAdditionalBytes( data, pos, 4 )
		if (not(status)) then
			stdnse.print_debug("StatFsDecode: Failed to call GetAdditionalBytes")
			return -1, nil
		end
		pos, statfs.status = bin.unpack(">I", data, pos)

		if (statfs.status ~= NFS.StatCode[comm.version].NFS_OK) then
			if (NFS.StatMsg[statfs.status]) then
				stdnse.print_debug(string.format("STATFS query failed: %s", NFS.StatMsg[statfs.status]))
			else
				stdnse.print_debug(string.format("STATFS query failed: code %d", statfs.status))
			end
			return -1, nil
		end

		status, data = comm:GetAdditionalBytes( data, pos, 20 )
		if (not(status)) then
			stdnse.print_debug("StatFsDecode: Failed to call GetAdditionalBytes")
			return -1, nil
		end
		pos, statfs.transfer_size, statfs.block_size, 
		statfs.total_blocks, statfs.free_blocks, 
		statfs.available_blocks = bin.unpack(">IIIII", data, pos )
		return pos, statfs
	end,
}

Helper = {

	--- Lists the NFS exports on the remote host
	-- This function abstracts the RPC communication with the portmapper from the user
	--
	-- @param host table
	-- @param port table
	-- @return status true on success, false on failure
	-- @return result table of string entries or error message on failure
	ShowMounts = function( host, port )

		local status, result, mounts 
		local mountd, mnt_comm
		local mnt = Mount:new()
		local portmap = Portmap:new()

		status, mountd = Helper.GetProgramInfo( host, port, "mountd")
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.ShowMounts: GetProgramInfo failed")
			return status, "rpc.Helper.ShowMounts: GetProgramInfo failed"
		end

		mnt_comm = Comm:new('mountd', mountd.version)
		status, result = mnt_comm:Connect(host, mountd.port)
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.ShowMounts: %s", result)
			return false, result
		end
		status, mounts = mnt:Export(mnt_comm)
		mnt_comm:Disconnect()
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.ShowMounts: %s", mounts)
		end
		return status, mounts
	end,

        --- Mounts a remote NFS export and returns the file handle
        --
        -- This is a high level function to be used by NSE scripts
        -- To close the mounted NFS export use UnmountPath() function
        --
        -- @param host table
        -- @param port table
        -- @param path string containing the path to mount
        -- @return on success a Comm object which can be
        --         used later as a parameter by low level Mount
        --         functions, on failure returns nil.
        -- @return on success the filehandle of the NFS export as
        --         a string, on failure returns the error message.
        MountPath = function(host, port, path)
          local fhandle, status, err
          local mountd, mnt_comm
          local mnt = Mount:new()

	  status, mountd = Helper.GetProgramInfo( host, port, "mountd")
	  if not status then
	    stdnse.print_debug("rpc.Helper.MountPath: %s", mountd)
	    return nil, mountd
	  end

	  mnt_comm = Comm:new("mountd", mountd.version)

	  status, err = mnt_comm:Connect(host, mountd.port)
	  if not status then
	    stdnse.print_debug("rpc.Helper.MountPath: %s", err)
	    return nil, err
	  end

	  status, fhandle = mnt:Mount(mnt_comm, path)
	  if not status then
	    mnt_comm:Disconnect()
	    stdnse.print_debug("rpc.Helper.MountPath: %s", fhandle)
	    return nil, fhandle
	  end

	  return mnt_comm, fhandle
	end,

        --- Unmounts a remote mounted NFS export
        --
        -- This is a high level function to be used by NSE scripts
        -- This function must be used to unmount a NFS point
        -- mounted by MountPath()
        --
        -- @param Comm object returned from a previous call to
        --        MountPath()
        -- @param path string containing the path to unmount
        -- @return true on success or nil on failure
        -- @return error message on failure
        UnmountPath = function(mnt_comm, path)
          local mnt = Mount:new()
	  local status, ret = mnt:Unmount(mnt_comm, path)	
	  mnt_comm:Disconnect()
	  if not status then
	    stdnse.print_debug("rpc.Helper.UnmountPath: %s", ret)
	    return nil, ret
	  end

	  return status, nil
        end,

        --- Connects to a remote NFS server
        --
        -- This is a high level function to be used by NSE scripts
        -- To close the NFS connection use NfsClose() function
        --
        -- @param host table
        -- @param port table
        -- @return on success a Comm object which can be
        --         used later as a parameter by low level NFS
        --         functions, on failure returns nil.
        -- @return error message on failure.
        NfsOpen = function(host, port)
          local nfs_comm, nfsd, status, err

	  status, nfsd = Helper.GetProgramInfo(host, port, "nfs")
	  if not status then
	    stdnse.print_debug("rpc.Helper.NfsProc: %s", nfsd)
	    return nil, nfsd
	  end

	  nfs_comm = Comm:new('nfs', nfsd.version)
	  status, err = nfs_comm:Connect(host, nfsd.port)
	  if not status then
	    stdnse.print_debug("rpc.Helper.NfsProc: %s", err)
	    return nil, err
	  end

	  return nfs_comm, nil
	end,

        --- Closes the NFS connection
        --
        -- This is a high level function to be used by NSE scripts
        -- This function must be used close a NFS connection opened
        -- by NfsOpen() call
        --
        -- @param Comm object returned by NfsOpen()
        -- @return true on success or nil on failure
        -- @return error message on failure
	NfsClose = function(nfs_comm)
	  local status, ret = nfs_comm:Disconnect()
	  if not status then
	    stdnse.print_debug("rpc.Helper.NfsClose: %s", ret)
	    return nil, ret
	  end

	  return status, nil
	end,

	--- Retrieves NFS storage statistics
	--
	-- @param host table
	-- @param port table
	-- @param path string containing the nfs export path
	-- @return status true on success, false on failure
	-- @return statfs table with the fields <code>transfer_size</code>, <code>block_size</code>, 
	-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
	ExportStats = function( host, port, path )
		local fhandle
		local stats, status, result
		local mnt_comm, nfs_comm
		local mountd, nfsd = {}, {}
		local mnt, nfs = Mount:new(), NFS:new()
	
		status, mountd = Helper.GetProgramInfo( host, port, "mountd", 2)
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.ExportStats: %s", mountd)
			return status, mountd
		end

		status, nfsd = Helper.GetProgramInfo( host, port, "nfs", 2)
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.ExportStats: %s", nfsd)
			return status, nfsd
		end
		mnt_comm = Comm:new('mountd', mountd.version)
		nfs_comm = Comm:new('nfs', nfsd.version)

		-- TODO: recheck the version mismatch when adding NFSv4
		if (nfs_comm.version <= 2  and mnt_comm.version > 2) then
			stdnse.print_debug("rpc.Helper.ExportStats: versions mismatch, nfs v%d - mount v%d",
						nfs_comm.version, mnt_comm.version)
			return false, string.format("versions mismatch, nfs v%d - mount v%d",
						nfs_comm.version, mnt_comm.version)
		end
		status, result = mnt_comm:Connect(host, mountd.port)
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.ExportStats: %s", result)
			return status, result
		end
		status, result = nfs_comm:Connect(host, nfsd.port)
		if ( not(status) ) then
			mnt_comm:Disconnect()
			stdnse.print_debug("rpc.Helper.ExportStats: %s", result)
			return status, result
		end

		status, fhandle = mnt:Mount(mnt_comm, path)
		if ( not(status) ) then
			mnt_comm:Disconnect()
			nfs_comm:Disconnect()
			stdnse.print_debug("rpc.Helper.ExportStats: %s", fhandle)
			return status, fhandle
		end
		status, stats = nfs:StatFs(nfs_comm, fhandle)
		if ( not(status) ) then
			mnt_comm:Disconnect()
			nfs_comm:Disconnect()
			stdnse.print_debug("rpc.Helper.ExportStats: %s", stats)
			return status, stats
		end
		
		status, fhandle = mnt:Unmount(mnt_comm, path)
		mnt_comm:Disconnect()
		nfs_comm:Disconnect()
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.ExportStats: %s", fhandle)
			return status, fhandle
		end
		return true, stats
	end,

	--- Retrieves a list of files from the NFS export
	--
	-- @param host table
	-- @param port table
	-- @param path string containing the nfs export path
	-- @return status true on success, false on failure
	-- @return table of file table entries as described in <code>decodeReadDir</code>
	Dir = function( host, port, path )
		local fhandle
		local dirs, status, result
		local mountd, nfsd = {}, {}
		local mnt_comm, nfs_comm
		local mnt, nfs = Mount:new(), NFS:new()

		status, mountd = Helper.GetProgramInfo( host, port, "mountd")
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.Dir: %s", mountd)
			return status, mountd
		end

		status, nfsd = Helper.GetProgramInfo( host, port, "nfs")
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.Dir: %s", nfsd)
			return status, nfsd
		end

		mnt_comm = Comm:new('mountd', mountd.version)
		nfs_comm = Comm:new('nfs', nfsd.version)

		-- TODO: recheck the version mismatch when adding NFSv4
		if (nfs_comm.version <= 2  and mnt_comm.version > 2) then
			stdnse.print_debug("rpc.Helper.Dir: versions mismatch, nfs v%d - mount v%d",
					nfs_comm.version, mnt_comm.version)
			return false, string.format("versions mismatch, nfs v%d - mount v%d",
					nfs_comm.version, mnt_comm.version)
		end
		status, result = mnt_comm:Connect(host, mountd.port)
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.Dir: %s", result)
			return status, result
		end

		status, result = nfs_comm:Connect(host, nfsd.port)
		if ( not(status) ) then
			mnt_comm:Disconnect()
			stdnse.print_debug("rpc.Helper.Dir: %s", result)
			return status, result
		end

		status, fhandle = mnt:Mount(mnt_comm, path )
		if ( not(status) ) then
			mnt_comm:Disconnect()
			nfs_comm:Disconnect()
			stdnse.print_debug("rpc.Helper.Dir: %s", fhandle)
			return status, fhandle
		end

		status, dirs = nfs:ReadDir(nfs_comm, fhandle )
		if ( not(status) ) then
			mnt_comm:Disconnect()
			nfs_comm:Disconnect()
			stdnse.print_debug("rpc.Helper.Dir: %s", dirs)
			return status, dirs
		end
		
		status, fhandle = mnt:Unmount(mnt_comm, path)	
		mnt_comm:Disconnect()
		nfs_comm:Disconnect()	
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.Dir: %s", fhandle)
			return status, fhandle
		end
		return true, dirs
	end,

	--- Retrieves NFS Attributes
	--
	-- @param host table
	-- @param port table
	-- @param path string containing the nfs export path
	-- @return status true on success, false on failure
	-- @return statfs table with the fields <code>transfer_size</code>, <code>block_size</code>, 
	-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
	GetAttributes = function( host, port, path )
		local fhandle
		local attribs, status, result
		local mnt_comm, nfs_comm
		local mountd, nfsd = {}, {}
		local mnt, nfs = Mount:new(), NFS:new()

		status, mountd = Helper.GetProgramInfo( host, port, "mountd")
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.GetAttributes: %s", mountd)
			return status, mountd
		end

		status, nfsd = Helper.GetProgramInfo( host, port, "nfs")
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.GetAttributes: %s", nfsd)
			return status, nfsd
		end
		
		mnt_comm, result = Comm:new('mountd', mountd.version)
		nfs_comm, result = Comm:new('nfs', nfsd.version)

		-- TODO: recheck the version mismatch when adding NFSv4
		if (nfs_comm.version <= 2  and mnt_comm.version > 2) then
			stdnse.print_debug("rpc.Helper.GetAttributes: versions mismatch, nfs v%d - mount v%d",
					nfs_comm.version, mnt_comm.version)
			return false, string.format("versions mismatch, nfs v%d - mount v%d",
					nfs_comm.version, mnt_comm.version)
		end

		status, result = mnt_comm:Connect(host, mountd.port)
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.GetAttributes: %s", result)
			return status, result
		end

		status, result = nfs_comm:Connect(host, nfsd.port)
		if ( not(status) ) then
			mnt_comm:Disconnect()
			stdnse.print_debug("rpc.Helper.GetAttributes: %s", result)
			return status, result
		end

		status, fhandle = mnt:Mount(mnt_comm, path)
		if ( not(status) ) then
			mnt_comm:Disconnect()
			nfs_comm:Disconnect()
			stdnse.print_debug("rpc.Helper.GetAttributes: %s", fhandle)
			return status, fhandle
		end

		status, attribs = nfs:GetAttr(nfs_comm, fhandle)
		if ( not(status) ) then
			mnt_comm:Disconnect()
			nfs_comm:Disconnect()
			stdnse.print_debug("rpc.Helper.GetAttributes: %s", attribs)
			return status, attribs
		end

		status, fhandle = mnt:Unmount(mnt_comm, path)
	
		mnt_comm:Disconnect()
		nfs_comm:Disconnect()	
		if ( not(status) ) then
			stdnse.print_debug("rpc.Helper.GetAttributes: %s", fhandle)
			return status, fhandle
		end

		return true, attribs
	end,
	
	--- Queries the portmapper for a list of programs
	--
	-- @param host table
	-- @param port table
	-- @return status true on success, false on failure
	-- @return table containing the portmapper information as returned by 
	-- <code>Portmap.Dump</code>
	RpcInfo = function( host, port )
		local status, result
		local portmap = Portmap:new()
		local comm = Comm:new('rpcbind', 2)

		status, result = comm:Connect(host, port)
		if (not(status)) then
			stdnse.print_debug("rpc.Helper.RpcInfo: %s", result)
			return status, result
		end
		mutex "lock"
		status, result = portmap:Dump(comm)
		mutex "done"
		comm:Disconnect()
		if (not(status)) then
			stdnse.print_debug("rpc.Helper.RpcInfo: %s", result)
		end

		return status, result
	end,

	--- Queries the portmapper for a port for the specified RPC program
	--
	-- @param host table
	-- @param port table
	-- @param program_id number containing the RPC program ID
	-- @param protocol string containing either "tcp" or "udp"
	-- @return status true on success, false on failure
	-- @return table containing the portmapper information as returned by 
	-- <code>Portmap.Dump</code>
	GetPortForProgram = function( host, port, program_id, protocol )
		local status, result
		local portmap = Portmap:new()
		local comm = Comm:new('rpcbind', 2)
		
		status, result = comm:Connect(host, port)
		if (not(status)) then
			stdnse.print_debug("rpc.Helper.GetPortForProgram: %s", result)
			return status, result
		end

		status, result = portmap:GetPort(comm, program_id, protocol, 1 )
		comm:Disconnect()
		if (not(status)) then
			stdnse.print_debug("rpc.Helper.GetPortForProgram: %s", result)
		end
		
		return status, result
	end,
	
	--- Get RPC program information
	--
	-- @param host table
	-- @param port table
	-- @param program string containing the RPC program name
	-- @param max_version (optional) number containing highest version to retrieve
	-- @return status true on success, false on failure
	-- @return info table containing <code>port</code>, <code>port.number</code>
	-- <code>port.protocol</code> and <code>version</code>
	GetProgramInfo = function( host, port, program, max_version )
		local info

		local status, portmap_table = Helper.RpcInfo(host, port)
		if ( not(status) ) then
			return status, portmap_table
		end

		-- assume failure
		status = false

		for _, p in ipairs( RPC_PROTOCOLS ) do
			local tmp = portmap_table[Util.ProgNameToNumber(program)]

			if ( tmp and tmp[p] ) then
				info = {}
				info.port = {}
				info.port.number = tmp[p].port
				info.port.protocol = p
				-- choose the highest version available
				if ( not(RPC_version[program]) ) then
					info.version = tmp[p].version[#tmp[p].version]
					status = true
				else
					for i=#tmp[p].version, 1, -1 do
						if ( RPC_version[program].max >= tmp[p].version[i] ) then
							if ( not(max_version) ) then
								info.version = tmp[p].version[i]
								status = true
								break
							else
								if ( max_version >= tmp[p].version[i] ) then
									info.version = tmp[p].version[i]
									status = true
									break			
								end
							end
						end
					end
				end
				break
			end
		end

		return status, info
	end,

}

--- Static class containing mostly conversion functions
--  and File type codes and permissions emulation
Util =
{
        -- Symbolic letters for file permission codes
        Fperm =
        {
          owner =
          {
            -- S_IRUSR
            [0x00000100] = { idx = 1, char = "r" },
            -- S_IWUSR
            [0x00000080] = { idx = 2, char = "w" },
            -- S_IXUSR
            [0x00000040] = { idx = 3, char = "x" }, 
            -- S_ISUID
            [0x00000800] = { idx = 3, char = "S" },
          },
          group =
          {
            -- S_IRGRP
            [0x00000020] = { idx = 4, char = "r" },
            -- S_IWGRP
            [0x00000010] = { idx = 5, char = "w" },
            -- S_IXGRP
            [0x00000008] = { idx = 6, char = "x" },
            -- S_ISGID
            [0x00000400] = { idx = 6, char = "S" },
          },
          other =
          {
            -- S_IROTH
            [0x00000004] = { idx = 7, char = "r" },
            -- S_IWOTH
            [0x00000002] = { idx = 8, char = "w" },
            -- S_IXOTH
            [0x00000001] = { idx = 9, char = "x" },
            -- S_ISVTX
            [0x00000200] = { idx = 9, char = "t" },
          },
        },

        -- bit mask used to extract the file type code from a mode
        -- S_IFMT = 00170000 (octal)
        S_IFMT = 0xF000,

        FileType =
        {
          -- S_IFSOCK
          [0x0000C000] = { char = "s", str = "socket" },
          -- S_IFLNK
          [0x0000A000] = { char = "l", str = "symbolic link" },
          -- S_IFREG
          [0x00008000] = { char = "-", str = "file" },
          -- S_IFBLK
          [0x00006000] = { char = "b", str = "block device" },
          -- S_IFDIR
          [0x00004000] = { char = "d", str = "directory" },
          -- S_IFCHR
          [0x00002000] = { char = "c", str = "char device" },
          -- S_IFIFO
          [0x00001000] = { char = "p", str = "named pipe" },
        },

        --- Returns the file type as a char to be used as
        --  a first letter of the mode string
        FtypeToChar = function(mode)
          local code = bit.band(mode, Util.S_IFMT)
          if Util.FileType[code] then
            return Util.FileType[code].char
          else
            stdnse.print_debug(1,"FtypeToChar: Unkown file type, mode: %o", mode)
            return ""
          end
        end,


        --- Returns the file type as a string
        FtypeToString = function(mode)
          local code = bit.band(mode, Util.S_IFMT)
          if Util.FileType[code] then
            return Util.FileType[code].str
          else
            stdnse.print_debug(1,"FtypeToString: Unknown file type, mode: %o", mode)
            return ""
          end
        end,

        FmodeToOctalString = function(mode)
          local code = bit.band(mode, Util.S_IFMT)
          if Util.FileType[code] then
            code = bit.bxor(mode, code)
          else
            code = mode
            stdnse.print_debug(1,"FmodeToOctalString: Unknown file type, mode: %o", mode)
          end
          return stdnse.tooctal(code)
        end,

        FpermToString = function(mode)
          local tmpacl, acl = {}, ""
          for i = 1, 9 do
            tmpacl[i] = "-"
          end

          for user,_ in pairs(Util.Fperm) do
            local t = Util.Fperm[user]
            for i in pairs(t) do
              local code = bit.band(mode, i)
              if t[code] then
                -- save set-ID and sticky bits
               	if tmpacl[t[code].idx] == "x" then
              	  if t[code].char == "S" then
              	    tmpacl[t[code].idx] = "s"
              	  else
                    tmpacl[t[code].idx] = t[code].char
                  end
                elseif tmpacl[t[code].idx] == "S" then
                  if t[code].char == "x" then
                    tmpacl[t[code].idx] = "s"
                  end
                else
                  tmpacl[t[code].idx] = t[code].char
                end
              end
            end
          end

          for i = 1,#tmpacl do
            acl = acl .. tmpacl[i]
          end

          return acl
        end,

        --- Converts the NFS file attributes to a string.
        --
        -- An optional second argument is the mactime to use
        --
        -- @param attributes table returned by NFS GETATTR or ACCESS
        -- @param mactime to use, the default value is atime
        --        Possible values: mtime, atime, ctime
        -- @return String that represent the file attributes
        format_nfsfattr = function(attr, mactime)
          local time = "atime"
          if mactime then
            time = mactime
          end

          return string.format("%s%s  uid: %5d  gid: %5d  %6s  %s",
                                rpc.Util.FtypeToChar(attr.mode),
                                rpc.Util.FpermToString(attr.mode),
                                attr.uid,
                                attr.gid,
                                rpc.Util.SizeToHuman(attr.size),
                                rpc.Util.TimeToString(attr[time].seconds))
        end,

        unmarshall_nfsftype = function(pos, data)
          local ftype
          pos, ftype = bin.unpack(">I", data, pos)
          return pos, ftype
        end,

        unmarshall_nfsfmode = function(pos, data)
          local fmode
          pos, fmode = bin.unpack(">I", data, pos)
          return pos, fmode
        end,

        unmarshall_nfssize3 = function(pos, data)
          local size3
          pos, size3 = bin.unpack(">L", data, pos)
          return pos, size3
        end,

        unmarshall_nfsspecdata3 = function(pos, data)
          local specdata3 = {}
          pos, specdata3['specdata1'], specdata3['specdata2'] = bin.unpack(">II", data, pos)
          return pos, specdata3
        end,

        unmarshall_nfsfileid3 = function(pos, data)
          local fileid3
          pos, fileid3 = bin.unpack(">L", data, pos)
          return pos, fileid3
        end,

        unmarshall_nfstime = function(pos, data)
          local nfstime = {}

          pos, nfstime['seconds'], nfstime['nseconds'] = bin.unpack(">II", data, pos)
          return pos, nfstime
        end,

        unmarshall_nfsattr = function(data, pos, nfsversion)
          local attr = {}
          pos, attr.type = Util.unmarshall_nfsftype(pos, data)
          pos, attr.mode = Util.unmarshall_nfsfmode(pos, data)
          pos, attr.nlink, attr.uid, attr.gid = bin.unpack(">III", data, pos)

          if (nfsversion < 3) then
            pos, attr.size, attr.blocksize, attr.rdev, attr.blocks,
            attr.fsid, attr.fileid = bin.unpack(">IIIIII", data, pos)
          elseif (nfsversion == 3) then
            pos, attr.size = Util.unmarshall_nfssize3(pos, data)
            pos, attr.used = Util.unmarshall_nfssize3(pos, data)
            pos, attr.rdev = Util.unmarshall_nfsspecdata3(pos, data)
            pos, attr.fsid = bin.unpack(">L",data, pos)
            pos, attr.fileid = Util.unmarshall_nfsfileid3(pos, data)
          else
            stdnse.print_debug("unmarshall_nfsattr: Unsupported version %d",
                              nfsversion)
            return -1, nil
          end

          pos, attr.atime = Util.unmarshall_nfstime(pos, data)
          pos, attr.mtime = Util.unmarshall_nfstime(pos, data)
          pos, attr.ctime = Util.unmarshall_nfstime(pos, data)

          return pos, attr
        end,

        --- Returns a string containing date and time
        TimeToString = function(time) 
            return os.date("!%F %H:%M", time)
        end,

        --- Converts the size in bytes to a human readable format
        --
        -- An optional second argument is the size of a block
        -- @usage
        -- size_tohuman(1024) --> 1024.0B
        -- size_tohuman(926548776) --> 883.6M
        -- size_tohuman(246548, 1024) --> 240.8K
        -- size_tohuman(246548, 1000) --> 246.5K
        --
        -- @param size in bytes
        -- @param blocksize represents the number of bytes per block
        --        Possible values are: 1024 or 1000
        --        Default value is: 1024
        -- @return String that represent the size in the human
        --         readable format
        SizeToHuman = function(size, blocksize)
          local bs, idx = 1024, 1
          local unit = { "B", "K", "M", "G" }
	  if blocksize and blocksize == 1000 then
	    bs = blocksize
	  end
          for i=1, #unit do
            if (size > bs) then
              size = size / bs
              idx = idx + 1
            end
          end
          return string.format("%.1f%s", size, unit[idx])
        end,
	
	--- Converts a RPC program name to it's equivalent number
	--
	-- @param prog_name string containing the name of the RPC program
	-- @return num number containing the program ID
	ProgNameToNumber = function(prog_name)
		local status
		
		if not( RPC_PROGRAMS ) then
			status, RPC_PROGRAMS = datafiles.parse_rpc()
			if ( not(status) ) then
				return
			end
		end
		for num, name in pairs(RPC_PROGRAMS) do
			if ( prog_name == name ) then
				return num
			end
		end
		
		return
	end,
	
	--- Converts the RPC program number to it's equivalent name
	--
	-- @param num number containing the RPC program identifier
	-- @return string containing the RPC program name
	ProgNumberToName = function( num )
		local status
		
		if not( RPC_PROGRAMS ) then
			status, RPC_PROGRAMS = datafiles.parse_rpc()
			if ( not(status) ) then
				return
			end
		end
		return RPC_PROGRAMS[num]
	end,
	
	--- Converts a numeric ACL mode as returned from <code>mnt.GetAttr</code>
	--  to octal
	--
	-- @param num number containing the ACL mode
	-- @return num containing the octal ACL mode
	ToAclMode = function( num )
		return ( ("%o"):format(bit.bxor(num, 0x4000)) )
	end,
	
	--- Converts a numeric ACL to it's character equivalent eg. (rwxr-xr-x)
	--
	-- @param num number containing the ACL mode
	-- @return string which represents the ACL mode
	ToAclText = function( num )
		local mode = num
		local txtmode = ""

		for i=0,2 do
			if ( bit.band( mode, bit.lshift(0x01, i*3) ) == bit.lshift(0x01, i*3) ) then
				-- Check for SUID or SGID
				if ( i>0 and bit.band( mode, 0x400 * i ) == 0x400 * i ) then
					txtmode = "s" .. txtmode
				else
					txtmode = "x" .. txtmode
				end
			else
				if ( i>0 and bit.band( mode, 0x400 * i ) == 0x400 * i ) then
					txtmode = "S" .. txtmode
				else
					txtmode = "-" .. txtmode
				end
			end
			if ( bit.band( mode, bit.lshift(0x02, i*3) ) == bit.lshift(0x02, i*3) ) then
				txtmode = "w" .. txtmode
			else
				txtmode = "-" .. txtmode
			end
			if ( bit.band( mode, bit.lshift(0x04, i*3) ) == bit.lshift(0x04, i*3) ) then
				txtmode = "r" .. txtmode
			else
				txtmode = "-" .. txtmode
			end
		end
		
		if ( bit.band(mode, 0x4000) == 0x4000 ) then
			txtmode = "d" .. txtmode
		else
			txtmode = "-" .. txtmode
		end
	
		return txtmode
	end,
	
	--
	-- Calculates the number of fill bytes needed
	-- @param length contains the length of the string
	-- @return the amount of pad needed to be divideable by 4
	CalcFillBytes = function(length)
	    -- calculate fill bytes
	    if math.mod( length, 4 ) ~= 0 then
	    	return (4 - math.mod( length, 4))
	    else
	    	return 0
	    end
	end
	
}
