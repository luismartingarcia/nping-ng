
/***************************************************************************
 * NmapOps.cc -- The NmapOps class contains global options, mostly based   *
 * on user-provided command-line settings.                                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2008 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://nmap.org to download Nmap.                                       *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */
#include "nmap.h"
#include "nbase.h"
#include "NmapOps.h"
#include "services.h"
#include "utils.h"
#ifdef WIN32
#include "winfix.h"
#endif

NmapOps o;

NmapOps::NmapOps() {
  datadir = NULL;
  xsl_stylesheet = NULL;
  Initialize();
}

NmapOps::~NmapOps() {
  if (datadir) free(datadir);
  if (xsl_stylesheet) free(xsl_stylesheet);
}

void NmapOps::ReInit() {
  Initialize();
}

// no setpf() because it is based on setaf() values
int NmapOps::pf() {
  return (af() == AF_INET)? PF_INET : PF_INET6;
}

int NmapOps::SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
  if (sourcesocklen <= 0)
    return 1;
  assert(sourcesocklen <= sizeof(*ss));
  if (ss)
    memcpy(ss, &sourcesock, sourcesocklen);
  if (ss_len)
    *ss_len = sourcesocklen;
  return 0;
}

/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void NmapOps::setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&sourcesock, ss, ss_len);
  sourcesocklen = ss_len;
}

struct in_addr NmapOps::v4source() {
 const struct in_addr *addy = v4sourceip();
  struct in_addr in;
  if (addy) return *addy;
  in.s_addr = 0;
  return in;
}

const struct in_addr *NmapOps::v4sourceip() {
   struct sockaddr_in *sin = (struct sockaddr_in *) &sourcesock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
}

// Number of milliseconds since getStartTime().  The current time is an
// optional argument to avoid an extra gettimeofday() call.
int NmapOps::TimeSinceStartMS(struct timeval *now) {
  struct timeval tv;
  if (!now)
    gettimeofday(&tv, NULL);
  else tv = *now;

  return TIMEVAL_MSEC_SUBTRACT(tv, start_time);
}

// Convert a filename to a file:// URL. The return value must be freed.
char *filename_to_url(const char *filename) {
  std::string url(filename);

#if WIN32
  for (std::string::iterator p = url.begin(); p != url.end(); p++) {
    if (*p == '\\')
      *p = '/';
  }
  /* Put a pseudo-root directory before "C:/" or whatever. */
  url = "/" + url;
#endif
  url = "file://" + url;

  return strdup(url.c_str());
}

void NmapOps::Initialize() {
  char tmpxsl[MAXPATHLEN];

  setaf(AF_INET);
#if defined WIN32 || defined __amigaos__
  isr00t = 1;
#else
  if (getenv("NMAP_PRIVILEGED"))
    isr00t = 1;
  else if (getenv("NMAP_UNPRIVILEGED"))
    isr00t = 0;
  else
    isr00t = !(geteuid());
#endif
  debugging = 0;
  verbose = 0;
  min_packet_send_rate = 0.0; /* Unset. */
  max_packet_send_rate = 0.0; /* Unset. */
  randomize_hosts = 0;
  sendpref = PACKET_SEND_NOPREF;
  spoofsource = 0;
  fastscan = 0;
  device[0] = '\0';
  interactivemode = 0;
  ping_group_sz = PING_GROUP_SZ;
  nogcc = 0;
  generate_random_ips = 0;
  reference_FPs = NULL;
  magic_port = 33000 + (get_random_uint() % 31000);
  magic_port_set = 0;
  timing_level = 3;
  max_parallelism = 0;
  min_parallelism = 0;
  max_os_tries = 5;
  max_rtt_timeout = MAX_RTT_TIMEOUT;
  min_rtt_timeout = MIN_RTT_TIMEOUT;
  initial_rtt_timeout = INITIAL_RTT_TIMEOUT;
  max_retransmissions = MAX_RETRANSMISSIONS;
  min_host_group_sz = 1;
  max_host_group_sz = 100000; // don't want to be restrictive unless user sets
  max_tcp_scan_delay = MAX_TCP_SCAN_DELAY;
  max_udp_scan_delay = MAX_UDP_SCAN_DELAY;
  max_ips_to_scan = 0;
  extra_payload_length = 0;
  extra_payload = NULL;
  scan_delay = 0;
  open_only = false;
  scanflags = -1;
  defeat_rst_ratelimit = 0;
  resume_ip.s_addr = 0;
  osscan_limit = 0;
  osscan_guess = 0;
  numdecoys = 0;
  decoyturn = -1;
  osscan = 0;
  servicescan = 0;
  override_excludeports = 0;
  version_intensity = 7;
  pingtype = PINGTYPE_UNKNOWN;
  listscan = pingscan = allowall = ackscan = bouncescan = connectscan = 0;
  rpcscan = nullscan = xmasscan = fragscan = synscan = windowscan = 0;
  maimonscan = idlescan = finscan = udpscan = ipprotscan = noresolve = 0;
  append_output = 0;
  memset(logfd, 0, sizeof(FILE *) * LOG_NUM_FILES);
  ttl = -1;
  badsum = 0;
  nmap_stdout = stdout;
  gettimeofday(&start_time, NULL);
  pTrace = vTrace = false;
  reason = false;
  if (datadir) free(datadir);
  datadir = NULL;
  if (xsl_stylesheet) free(xsl_stylesheet);
  if (nmap_fetchfile(tmpxsl, sizeof(tmpxsl), "nmap.xsl") == 1) {
    xsl_stylesheet = filename_to_url(tmpxsl);
  } else {
#if WIN32
    /* Use a relative URL on Windows if nmap_fetchfile failed. It won't work,
       but it gives a clue that there is an nmap.xsl somewhere. */
    Strncpy(tmpxsl, "nmap.xsl", sizeof(tmpxsl));
    xsl_stylesheet = strdup(tmpxsl);
#else
    Snprintf(tmpxsl, sizeof(tmpxsl), "%s/nmap.xsl", NMAPDATADIR);
    xsl_stylesheet = filename_to_url(tmpxsl);
#endif
  }
  spoof_mac_set = false;
  mass_dns = true;
  log_errors = false;
  resolve_all = 0;
  dns_servers = NULL;
  noninteractive = false;
  current_scantype = STYPE_UNKNOWN;
  ipoptions = NULL;
  ipoptionslen = 0;
  ipopt_firsthop = 0;
  ipopt_lasthop  = 0;  
  release_memory = false;
  topportlevel = -1;
#ifndef NOLUA
  script = 0;
  scriptversion = 0;
  scripttrace = 0;
  scriptupdatedb = 0;
#endif
  memset(&sourcesock, 0, sizeof(sourcesock));
  sourcesocklen = 0;
}

bool NmapOps::TCPScan() {
  return ackscan|bouncescan|connectscan|finscan|idlescan|maimonscan|nullscan|synscan|windowscan|xmasscan;
}

bool NmapOps::UDPScan() {
  return udpscan;
}

  /* this function does not currently cover cases such as TCP SYN ping
     scan which can go either way based on whether the user is root or
     IPv6 is being used.  It will return false in those cases where a
     RawScan is not neccessarily used. */
bool NmapOps::RawScan() {
  if (ackscan|finscan|idlescan|ipprotscan|maimonscan|nullscan|osscan|synscan|udpscan|windowscan|xmasscan)
    return true;
  if (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS|PINGTYPE_TCP_USE_ACK|PINGTYPE_UDP))
    return true;

   return false; 
}


void NmapOps::ValidateOptions() {
#ifdef WIN32
	const char *privreq = "that WinPcap version 3.1 or higher and iphlpapi.dll be installed. You seem to be missing one or both of these.  Winpcap is available from http://www.winpcap.org.  iphlpapi.dll comes with Win98 and later operating sytems and NT 4.0 with SP4 or greater.  For previous windows versions, you may be able to take iphlpapi.dll from another system and place it in your system32 dir (e.g. c:\\windows\\system32)";
#else
	const char *privreq = "root privileges";
#endif


  /* Insure that at least one scantype is selected */
  if (TCPScan() + UDPScan() + ipprotscan + listscan + pingscan == 0) {
    if (isr00t && af() == AF_INET)
      synscan++;
    else connectscan++;
    //    if (verbose) error("No tcp, udp, or ICMP scantype specified, assuming %s scan. Use -sP if you really don't want to portscan (and just want to see what hosts are up).", synscan? "SYN Stealth" : "vanilla tcp connect()");
  }

  if (pingtype != PINGTYPE_NONE && spoofsource) {
    error("WARNING:  If -S is being used to fake your source address, you may also have to use -e <interface> and -PN .  If you are using it to specify your real source address, you can ignore this warning.");
  }

  if (pingtype != PINGTYPE_NONE && idlescan) {
    error("WARNING: Many people use -PN w/Idlescan to prevent pings from their true IP.  On the other hand, timing info Nmap gains from pings can allow for faster, more reliable scans.");
    sleep(2); /* Give ppl a chance for ^C :) */
  }

 if (numdecoys > 1 && idlescan) {
    error("WARNING: Your decoys won't be used in the Idlescan portion of your scanning (although all packets sent to the target are spoofed anyway");
  }

 if (connectscan && spoofsource) {
    error("WARNING:  -S will only affect the source address used in a connect() scan if you specify one of your own addresses.  Use -sS or another raw scan if you want to completely spoof your source address, but then you need to know what you're doing to obtain meaningful results.");
  }

 if ((pingtype & PINGTYPE_UDP) && (!isr00t || af() != AF_INET)) {
   fatal("Sorry, UDP Ping (-PU) only works if you are root (because we need to read raw responses off the wire) and only for IPv4 (cause fyodor is too lazy right now to add IPv6 support and nobody has sent a patch)");
 }

 if ((pingtype & PINGTYPE_PROTO) && (!isr00t || af() != AF_INET)) {
   fatal("Sorry, IPProto Ping (-PO) only works if you are root (because we need to read raw responses off the wire) and only for IPv4");
 }

 if (ipprotscan + (TCPScan() || UDPScan()) + listscan + pingscan > 1) {
   fatal("Sorry, the IPProtoscan, Listscan, and Pingscan (-sO, -sL, -sP) must currently be used alone rather than combined with other scan types.");
 }

 if ((pingscan && pingtype == PINGTYPE_NONE)) {
    fatal("-PN (skip ping) is incompatable with -sP (ping scan).  If you only want to enumerate hosts, try list scan (-sL)");
  }

 if (pingscan && (TCPScan() || UDPScan() || ipprotscan || listscan)) {
   fatal("Ping scan is not valid with any other scan types (the other ones all include a ping scan");
 }

 if (af() == AF_INET6 && (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS))) {
   fatal("ICMP Echo, Timestamp and Address Mask pings are only valid for IPv4.");
 }

 if (sendpref == PACKET_SEND_NOPREF) {
#ifdef WIN32
   sendpref = PACKET_SEND_ETH_STRONG;
#else
   sendpref = PACKET_SEND_IP_WEAK;
#endif
 }
/* We start with stuff users should not do if they are not root */
  if (!isr00t) {
    
    if (ackscan|finscan|idlescan|ipprotscan|maimonscan|nullscan|synscan|udpscan|windowscan|xmasscan) {
      fatal("You requested a scan type which requires %s.", privreq);
    }
    
    if (numdecoys > 0) {
      fatal("Sorry, but decoys (-D) require %s.", privreq);
    }
    
    if (fragscan) {
      fatal("Sorry, but fragscan requires %s.", privreq);
    }
    
    if (osscan) {
      fatal("TCP/IP fingerprinting (for OS scan) requires %s.", privreq);
    }
  }
  
  
  if (numdecoys > 0 && rpcscan) {
    error("WARNING:  RPC scan currently does not make use of decoys so don't count on that protection");
  }
  
  if (bouncescan && pingtype != PINGTYPE_NONE) 
    log_write(LOG_STDOUT, "Hint: if your bounce scan target hosts aren't reachable from here, remember to use -PN so we don't try and ping them prior to the scan\n");
  
  if (ackscan+bouncescan+connectscan+finscan+idlescan+maimonscan+nullscan+synscan+windowscan+xmasscan > 1)
    fatal("You specified more than one type of TCP scan.  Please choose only one of -sA, -b, -sT, -sF, -sI, -sM, -sN, -sS, -sW, and -sX");
  
  if (numdecoys > 0 && (bouncescan || connectscan)) {
    error("WARNING: Decoys are irrelevant to the bounce or connect scans");
  }
  
  if (fragscan && !(ackscan|finscan|maimonscan|nullscan|synscan|windowscan|xmasscan) && \
      !(pingtype&(PINGTYPE_ICMP_TS|PINGTYPE_TCP)) && !(fragscan == 8 && pingtype&PINGTYPE_ICMP_MASK) && \
      !(extra_payload_length + 8 > fragscan)) {
    fatal("Fragscan only works with TCP, ICMP Timestamp or ICMP Mask (mtu=8) ping types or ACK, FIN, Maimon, NULL, SYN, Window, and XMAS scan types");
  }
  
  if (osscan && bouncescan)
    error("Combining bounce scan with OS scan seems silly, but I will let you do whatever you want!");
  
#if !defined(LINUX) && !defined(OPENBSD) && !defined(FREEBSD) && !defined(NETBSD)
  if (fragscan) {
    error("Warning: Packet fragmentation selected on a host other than Linux, OpenBSD, FreeBSD, or NetBSD.  This may or may not work.");
  }
#endif
  
  if (osscan && pingscan) {
    fatal("WARNING:  OS Scan is unreliable with a ping scan.  You need to use a scan type along with it, such as -sS, -sT, -sF, etc instead of -sP");
  }

  if (osscan && ipprotscan) {
    error("WARNING: Disabling OS Scan (-O) as it is incompatible with the IPProto Scan (-sO)");
    osscan = 0;
  }

  if (servicescan && ipprotscan) {
    error("WARNING: Disabling Service Scan (-sV) as it is incompatible with the IPProto Scan (-sO)");
    servicescan = 0;
  }

  if (servicescan && pingscan)
    servicescan = 0;

  if (defeat_rst_ratelimit && !synscan) {
      fatal("Option --defeat-rst-ratelimit works only with a SYN scan (-sS)");
  }
  
  if (resume_ip.s_addr && generate_random_ips)
    resume_ip.s_addr = 0;
  
  if (magic_port_set && connectscan) {
    error("WARNING:  -g is incompatible with the default connect() scan (-sT).  Use a raw scan such as -sS if you want to set the source port.");
  }

  if (max_parallelism && min_parallelism && (min_parallelism > max_parallelism)) {
    fatal("--min-parallelism=%i must be less than or equal to --max-parallelism=%i",min_parallelism,max_parallelism);
  }

  if (min_packet_send_rate != 0.0 && max_packet_send_rate != 0.0 && min_packet_send_rate > max_packet_send_rate) {
    fatal("--min-rate=%g must be less than or equal to --max-rate=%g", min_packet_send_rate, max_packet_send_rate);
  }
  
  if (af() == AF_INET6 && (numdecoys|osscan|bouncescan|fragscan|ackscan|finscan|idlescan|ipprotscan|maimonscan|nullscan|synscan|udpscan|windowscan|xmasscan)) {
    fatal("Sorry -- IPv6 support is currently only available for connect() scan (-sT), ping scan (-sP), and list scan (-sL).  OS detection and decoys are also not supported with IPv6.  Further support is under consideration.");
  }

  if (af() != AF_INET) mass_dns = false;

  /* Prevent performance values from getting out of whack */
  if (min_parallelism > max_parallelism)
    max_parallelism = min_parallelism;

  if(ipoptions && osscan)
    error("WARNING: Ip options are NOT used while OS scanning!");

#ifndef NOLUA
  /* Make sure nmap.registry.args is available (even if it's empty) */
  if (!scriptargs)
    scriptargs = strdup("");
#endif
}

void NmapOps::setMaxOSTries(int mot) {
  if (mot <= 0) 
    fatal("%s: value must be at least 1", __func__);
  max_os_tries = mot; 
}

void NmapOps::setMaxRttTimeout(int rtt) 
{ 
  if (rtt <= 0) fatal("%s: maximum round trip time must be greater than 0", __func__);
  max_rtt_timeout = rtt; 
  if (rtt < min_rtt_timeout) min_rtt_timeout = rtt; 
  if (rtt < initial_rtt_timeout) initial_rtt_timeout = rtt;
}

void NmapOps::setMinRttTimeout(int rtt) 
{ 
  if (rtt < 0) fatal("%s: minimum round trip time must be at least 0", __func__);
  min_rtt_timeout = rtt; 
  if (rtt > max_rtt_timeout) max_rtt_timeout = rtt;  
  if (rtt > initial_rtt_timeout) initial_rtt_timeout = rtt;
}

void NmapOps::setInitialRttTimeout(int rtt) 
{ 
  if (rtt <= 0) fatal("%s: initial round trip time must be greater than 0", __func__);
  initial_rtt_timeout = rtt; 
  if (rtt > max_rtt_timeout) max_rtt_timeout = rtt;  
  if (rtt < min_rtt_timeout) min_rtt_timeout = rtt;
}

void NmapOps::setMaxRetransmissions(int max_retransmit)
{
    if (max_retransmit < 0)
        fatal("%s: must be positive", __func__);
    max_retransmissions = max_retransmit;
}


void NmapOps::setMinHostGroupSz(unsigned int sz) {
  if (sz > max_host_group_sz)
    fatal("Minimum host group size may not be set to greater than maximum size (currently %d)\n", max_host_group_sz);
  min_host_group_sz = sz;
}

void NmapOps::setMaxHostGroupSz(unsigned int sz) {
  if (sz < min_host_group_sz)
    fatal("Maximum host group size may not be set to less than the maximum size (currently %d)\n", min_host_group_sz);
  if (sz <= 0)
    fatal("Max host size must be at least 1");
  max_host_group_sz = sz;
}

  /* Sets the Name of the XML stylesheet to be printed in XML output.
     If this is never called, a default stylesheet distributed with
     Nmap is used.  If you call it with NULL as the xslname, no
     stylesheet line is printed. */
void NmapOps::setXSLStyleSheet(const char *xslname) {
  if (xsl_stylesheet) free(xsl_stylesheet);
  xsl_stylesheet = xslname? strdup(xslname) : NULL;
}

void NmapOps::setSpoofMACAddress(u8 *mac_data) {
  memcpy(spoof_mac, mac_data, 6);
  spoof_mac_set = true;
}

#ifndef NOLUA
void NmapOps::chooseScripts(char* argument) {
	char *ap;

	ap = strtok(argument, ",");
	while(ap != NULL) {
		chosenScripts.push_back(std::string(ap));
		ap = strtok(NULL, ",");
	}
}
#endif
