--- Utility functions for manipulating and comparing IP addresses.
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

local type     = type
local table    = table
local string   = string
local ipairs   = ipairs
local tonumber = tonumber

local stdnse   = require "stdnse"

module ( "ipOps" )



---
-- Checks to see if the supplied IP address is part of a non-routable
-- address space.
--
-- The non-Internet-routable address spaces known to this function are
-- * IPv4 Loopback (RFC3330)
-- * IPv4 Private Use (RFC1918)
-- * IPv4 Link Local (RFC3330)
-- * IPv6 Unspecified and Loopback (RFC3513)
-- * IPv6 Unique Local Unicast (RFC4193)
-- * IPv6 Link Local Unicast (RFC4291)
-- @param ip  String representing an IPv4 or IPv6 address.  Shortened notation
-- is permitted.
-- @usage
-- local is_private = ipOps.isPrivate( "192.168.1.1" )
-- @return True or false (or <code>nil</code> in case of an error).
-- @return String error message in case of an error.
isPrivate = function( ip )

  ip, err = expand_ip( ip )
  if err then return nil, err end

  local ipv4_private = { "10/8", "127/8", "169.254/16", "172.15/12", "192.168/16" }
  local ipv6_private = { "::/127", "FC00::/7", "FE80::/10" }
  local t, is_private = {}
  if ip:match( ":" ) then
    t = ipv6_private
  else
    t = ipv4_private
  end

  for _, range in ipairs( t ) do
    is_private, err = ip_in_range( ip, range )
    -- return as soon as is_private is true or err
    if is_private then return true end
    if err then return nil, err end
  end
  return false

end



---
-- Converts the supplied IPv4 address into a DWORD value.
--
-- For example, the address a.b.c.d becomes (((a*256+b)*256+c)*256+d).
--
-- Note: IPv6 addresses are not supported. Currently, numbers in NSE are
-- limited to 10^14, and consequently not all IPv6 addresses can be
-- represented.
-- @param ip  String representing an IPv4 address.  Shortened notation is
-- permitted.
-- @usage
-- local dword = ipOps.todword( "73.150.2.210" )
-- @return Number corresponding to the supplied IP address (or <code>nil</code>
-- in case of an error).
-- @return String error message in case of an error.
todword = function( ip )

  if type( ip ) ~= "string" or ip:match( ":" ) then
    return nil, "Error in ipOps.todword: Expected IPv4 address."
  end

  local n, ret = {}
  n, err = get_parts_as_number( ip )
  if err then return nil, err end

  ret = (((n[1]*256+n[2]))*256+n[3])*256+n[4]

  return ret

end



---
-- Separates the supplied IP address into its constituent parts and
-- returns them as a table of numbers.
--
-- For example, the address 139.104.32.123 becomes { 139, 104, 32, 123 }.
-- @usage
-- local a, b, c, d;
-- local t, err = ipOps.get_parts_as_number( "139.104.32.123" )
-- if t then a, b, c, d = unpack( t ) end
-- @param ip  String representing an IPv4 or IPv6 address.  Shortened notation
-- is permitted.
-- @return   Array of numbers for each part of the supplied IP address (or
-- <code>nil</code> in case of an error).
-- @return String error message in case of an error.
get_parts_as_number = function( ip )

  ip, err = expand_ip( ip )
  if err then return nil, err end

  local pattern, base
  if ip:match( ":" ) then
    pattern = "%x+"
    base = 16
  else
    pattern = "%d+"
    base = 10
  end
  local t = {}
  for part in string.gmatch(ip, pattern) do
    t[#t+1] = tonumber( part, base )
  end

  return t

end



---
-- Compares two IP addresses (from the same address family).
-- @param left   String representing an IPv4 or IPv6 address.  Shortened
-- notation is permitted.
-- @param op     A comparison operator which may be one of the following
-- strings: <code>"eq"</code>, <code>"ge"</code>, <code>"le"</code>,
-- <code>"gt"</code> or <code>"lt"</code> (respectively ==, >=, <=, >, <).
-- @param right  String representing an IPv4 or IPv6 address.  Shortened
-- notation is permitted.
-- @usage
-- if ipOps.compare_ip( "2001::DEAD:0:0:0", "eq", "2001:0:0:0:DEAD::" ) then
--   ...
-- end
-- @return True or false (or <code>nil</code> in case of an error).
-- @return String error message in case of an error.
compare_ip = function( left, op, right )

  if type( left ) ~= "string" or type( right ) ~= "string" then
    return nil, "Error in ipOps.compare_ip: Expected IP address as a string."
  end

  if ( left:match( ":" ) and not right:match( ":" ) ) or ( not left:match( ":" ) and right:match( ":" ) ) then
    return nil, "Error in ipOps.compare_ip: IP addresses must be from the same address family."
  end

  if op == "lt" or op == "le" then
    left, right = right, left
  elseif op ~= "eq" and op ~= "ge" and op ~= "gt" then
    return nil, "Error in ipOps.compare_ip: Invalid Operator."
  end

  local err ={}
  left, err[#err+1] = ip_to_bin( left )
  right, err[#err+1] = ip_to_bin( right )
  if #err > 0 then
    return nil, table.concat( err, " " )
  end

  if string.len( left ) ~= string.len( right ) then
      -- shouldn't happen...
      return nil, "Error in ipOps.compare_ip: Binary IP addresses were of different lengths."
  end

  -- equal?
  if ( op == "eq" or op == "le" or op == "ge" ) and left == right then
    return true
  elseif op == "eq" then
    return false
  end

  -- starting from the leftmost bit, subtract the bit in right from the bit in left
  local compare
  for i = 1, string.len( left ), 1 do
    compare = tonumber( string.sub( left, i, i ) ) - tonumber( string.sub( right, i, i ) )
    if compare == 1 then
      return true
    elseif compare == -1 then
      return false
    end
  end
  return false

end



---
-- Checks whether the supplied IP address is within the supplied range of IP
-- addresses.
--
-- The address and the range must both belong to the same address family.
-- @param ip     String representing an IPv4 or IPv6 address.  Shortened
-- notation is permitted.
-- @param range  String representing a range of IPv4 or IPv6 addresses in
-- first-last or CIDR notation (e.g.
-- <code>"192.168.1.1 - 192.168.255.255"</code> or
-- <code>"2001:0A00::/23"</code>).
-- @usage
-- if ipOps.ip_in_range( "192.168.1.1", "192/8" ) then ... end
-- @return True or false (or <code>nil</code> in case of an error).
-- @return String error message in case of an error.
ip_in_range = function( ip, range )

  local first, last, err = get_ips_from_range( range )
  if err then return nil, err end
  ip, err = expand_ip( ip )
  if err then return nil, err end
  if ( ip:match( ":" ) and not first:match( ":" ) ) or ( not ip:match( ":" ) and first:match( ":" ) ) then
    return nil, "Error in ipOps.ip_in_range: IP address is of a different address family to Range."
  end

  err = {}
  local ip_ge_first, ip_le_last
  ip_ge_first, err[#err+1] = compare_ip( ip, "ge", first )
  ip_le_last, err[#err+1] = compare_ip( ip, "le", last )
  if #err > 0 then
    return nil, table.concat( err, " " )
  end

  if ip_ge_first and ip_le_last then
    return true
  else
    return false
  end

end



---
-- Expands an IP address supplied in shortened notation.
-- Serves also to check the well-formedness of an IP address.
--
-- Note: IPv4in6 notated addresses will be returned in pure IPv6 notation unless
-- the IPv4 portion is shortened and does not contain a dot, in which case the
-- address will be treated as IPv6.
-- @param ip  String representing an IPv4 or IPv6 address in shortened or full notation.
-- @usage
-- local ip = ipOps.expand_ip( "2001::" )
-- @return    String representing a fully expanded IPv4 or IPv6 address (or
-- <code>nil</code> in case of an error).
-- @return String error message in case of an error.
expand_ip = function( ip )

  if type( ip ) ~= "string" or ip == "" then
    return nil, "Error in ipOps.expand_ip: Expected IP address as a string."
  end

  local err4 = "Error in ipOps.expand_ip: An address assumed to be IPv4 was malformed."

  if not ip:match( ":" ) then
    -- ipv4: missing octets should be "0" appended
    if ip:match( "[^\.0-9]" ) then
      return nil, err4
    end
    local octets = {}
    for octet in string.gmatch( ip, "%d+" ) do
      if tonumber( octet, 10 ) > 255 then return nil, err4 end
      octets[#octets+1] = octet
    end
    if #octets > 4 then return nil, err4 end
    while #octets < 4 do
      octets[#octets+1] = "0"
    end
    return ( table.concat( octets, "." ) )
  end

  if ip:match( "[^\.:%x]" ) then
    return nil, ( err4:gsub( "IPv4", "IPv6" ) )
  end

  -- preserve ::
  ip = string.gsub(ip, "::", ":z:")

  -- get a table of each hexadectet
  local hexadectets = {}
  for hdt in string.gmatch( ip, "[\.z%x]+" ) do
    hexadectets[#hexadectets+1] = hdt
  end

  -- deal with IPv4in6 (last hexadectet only)
  local t = {}
  if hexadectets[#hexadectets]:match( "[\.]+" ) then
    hexadectets[#hexadectets], err = expand_ip( hexadectets[#hexadectets] )
    if err then return nil, ( err:gsub( "IPv4", "IPv4in6" ) ) end
    t = stdnse.strsplit( "[\.]+", hexadectets[#hexadectets] )
    for i, v in ipairs( t ) do
      t[i] = tonumber( v, 10 )
    end
    hexadectets[#hexadectets] = stdnse.tohex( 256*t[1]+t[2] )
    hexadectets[#hexadectets+1] = stdnse.tohex( 256*t[3]+t[4] )
  end

  -- deal with :: and check for invalid address
  local z_done = false
  for index, value in ipairs( hexadectets ) do
    if value:match( "[\.]+" ) then
      -- shouldn't have dots at this point
      return nil, ( err4:gsub( "IPv4", "IPv6" ) )
    elseif value == "z" and z_done then
      -- can't have more than one ::
      return nil, ( err4:gsub( "IPv4", "IPv6" ) )
    elseif value == "z" and not z_done then
      z_done = true
      hexadectets[index] = "0"
      local bound = 8 - #hexadectets
      for i = 1, bound, 1 do
        table.insert( hexadectets, index+i, "0" )
      end
    elseif tonumber( value, 16 ) > 65535 then
      -- more than FFFF!
      return nil, ( err4:gsub( "IPv4", "IPv6" ) )
    end
  end

  -- make sure we have exactly 8 hexadectets
  if #hexadectets > 8 then return nil, ( err4:gsub( "IPv4", "IPv6" ) ) end
  while #hexadectets < 8 do
    hexadectets[#hexadectets+1] = "0"
  end

  return ( table.concat( hexadectets, ":" ) )

end



---
-- Returns the first and last IP addresses in the supplied range of addresses.
-- @param range  String representing a range of IPv4 or IPv6 addresses in either
-- CIDR or first-last notation.
-- @usage
-- first, last = ipOps.get_ips_from_range( "192.168.0.0/16" )
-- @return       String representing the first address in the supplied range (or
-- <code>nil</code> in case of an error).
-- @return       String representing the last address in the supplied range (or
-- <code>nil</code> in case of an error).
-- @return       String error message in case of an error.
get_ips_from_range = function( range )

  if type( range ) ~= "string" then
    return nil, nil, "Error in ipOps.get_ips_from_range: Expected a range as a string."
  end

  local first, last, prefix
  if range:match( "/" ) then
    first, prefix = range:match( "([%x%d:\.]+)/(%d+)" )
  elseif range:match( "-" ) then
    first, last = range:match( "([%x%d:\.]+)%s*\-%s*([%x%d:\.]+)" )
  end

  local err = {}
  if first and ( last or prefix ) then
    first, err[#err+1] = expand_ip( first )
  else
    return nil, nil, "Error in ipOps.get_ips_from_range: The range supplied could not be interpreted."
  end
  if last then
    last, err[#err+1] = expand_ip( last )
  elseif first and prefix then
    last, err[#err+1] = get_last_ip( first, prefix )
  end

  if first and last then
    if ( first:match( ":" ) and not last:match( ":" ) ) or ( not first:match( ":" ) and last:match( ":" ) ) then
      return nil, nil, "Error in ipOps.get_ips_from_range: First IP address is of a different address family to last IP address."
    end
    return first, last
  else
    return nil, nil, table.concat( err, " " )
  end

end



---
-- Calculates the last IP address of a range of addresses given an IP address in
-- the range and prefix length for that range.
-- @param ip      String representing an IPv4 or IPv6 address.  Shortened
-- notation is permitted.
-- @param prefix  Number or a string representing a decimal number corresponding
-- to a prefix length.
-- @usage
-- last = ipOps.get_last_ip( "192.0.0.0", 26 )
-- @return        String representing the last IP address of the range denoted
-- by the supplied parameters (or <code>nil</code> in case of an error).
-- @return String error message in case of an error.
get_last_ip = function( ip, prefix )

  local first, err = ip_to_bin( ip )
  if err then return nil, err end

  prefix = tonumber( prefix )
  if not prefix or ( prefix < 0 ) or ( prefix > string.len( first ) ) then
    return nil, "Error in ipOps.get_last_ip: Invalid prefix length."
  end

  local hostbits = string.sub( first, prefix + 1 )
  hostbits = string.gsub( hostbits, "0", "1" )
  local last = string.sub( first, 1, prefix ) .. hostbits
  last, err = bin_to_ip( last )
  if err then return nil, err end
  return last

end



---
-- Converts an IP address into a string representing the address as binary
-- digits.
-- @param ip  String representing an IPv4 or IPv6 address.  Shortened notation
-- is permitted.
-- @usage
-- bit_string = ipOps.ip_to_bin( "2001::" )
-- @return    String representing the supplied IP address as 32 or 128 binary
-- digits (or <code>nil</code> in case of an error).
-- @return    String error message in case of an error.
ip_to_bin = function( ip )

  ip, err = expand_ip( ip )
  if err then return nil, err end

  local t, mask = {}

  if not ip:match( ":" ) then
    -- ipv4 string
    for octet in string.gmatch( ip, "%d+" ) do
      t[#t+1] = stdnse.tohex( tonumber(octet) )
    end
    mask = "00"
  else
    -- ipv6 string
    for hdt in string.gmatch( ip, "%x+" ) do
      t[#t+1] = hdt
    end
    mask = "0000"
  end

  -- padding
  for i, v in ipairs( t ) do
    t[i] = mask:sub( 1, string.len( mask ) - string.len( v ) ) .. v
  end

  return hex_to_bin( table.concat( t ) )

end



---
-- Converts a string of binary digits into an IP address.
-- @param binstring  String representing an IP address as 32 or 128 binary
-- digits.
-- @usage
-- ip = ipOps.bin_to_ip( "01111111000000000000000000000001" )
-- @return           String representing an IP address (or <code>nil</code> in
-- case of an error).
-- @return           String error message in case of an error.
bin_to_ip = function( binstring )

  if type( binstring ) ~= "string" or binstring:match( "[^01]+" ) then
    return nil, "Error in ipOps.bin_to_ip: Expected string of binary digits."
  end

  if string.len( binstring ) == 32 then
    af = 4
  elseif string.len( binstring ) == 128 then
    af = 6
  else
    return nil, "Error in ipOps.bin_to_ip: Expected exactly 32 or 128 binary digits."
  end

  t = {}
  if af == 6 then
    local pattern = string.rep( "[01]", 16 )
    for chunk in string.gmatch( binstring, pattern ) do
      t[#t+1] = stdnse.tohex( tonumber( chunk, 2 ) )
    end
    return table.concat( t, ":" )
  end

  if af == 4 then
    local pattern = string.rep( "[01]", 8 )
    for chunk in string.gmatch( binstring, pattern ) do
      t[#t+1] = tonumber( chunk, 2 ) .. ""
    end
    return table.concat( t, "." )
  end

end



---
-- Converts a string of hexadecimal digits into the corresponding string of
-- binary digits.
--
-- Each hex digit results in four bits. This function is really just a wrapper
-- around <code>stdnse.tobinary</code>.
-- @param hex  String representing a hexadecimal number.
-- @usage
-- bin_string = ipOps.hex_to_bin( "F00D" )
-- @return     String representing the supplied number in binary digits (or
-- <code>nil</code> in case of an error).
-- @return     String error message in case of an error.
hex_to_bin = function( hex )

  if type( hex ) ~= "string" or hex == "" or hex:match( "[^%x]+" ) then
    return nil, "Error in ipOps.hex_to_bin: Expected string representing a hexadecimal number."
  end

  local t, mask, binchar = {}, "0000"
  for hexchar in string.gmatch( hex, "%x" ) do
      binchar = stdnse.tobinary( tonumber( hexchar, 16 ) )
      t[#t+1] = mask:sub( 1, string.len( mask ) - string.len( binchar ) ) .. binchar
  end
  return table.concat( t )

end
