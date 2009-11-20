
/***************************************************************************
 * output.cc -- Handles the Nmap output system.  This currently involves   *
 * console-style human readable output, XML output, Script |<iddi3         *
 * output, and the legacy greppable output (used to be called "machine     *
 * readable").  I expect that future output forms (such as HTML) may be    *
 * created by a different program, library, or script using the XML        *
 * output.                                                                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
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
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
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

#include "output.h"
#include "osscan.h"
#include "NmapOps.h"
#include "NmapOutputTable.h"
#include "MACLookup.h"
#include "portreasons.h"
#include "protocols.h"
#include "nmap_rpc.h"
#include "Target.h"
#include "utils.h"

#include <math.h>

#include <set>
#include <string>
#include <vector>
#include <list>

/* Workaround for lack of namespace std on HP-UX 11.00 */
namespace std {};
using namespace std;

extern NmapOps o;
static const char *logtypes[LOG_NUM_FILES] = LOG_NAMES;

/* Used in creating skript kiddie style output.  |<-R4d! */
static void skid_output(char *s) {
  int i;
  for (i = 0; s[i]; i++)
    /* We need a 50/50 chance here, use a random number */
    if ((get_random_u8() & 0x01) == 0)
      /* Substitutions commented out are not known to me, but maybe look nice */
      switch (s[i]) {
      case 'A':
        s[i] = '4';
        break;
        /*    case 'B': s[i]='8'; break;
           case 'b': s[i]='6'; break;
           case 'c': s[i]='k'; break;
           case 'C': s[i]='K'; break; */
      case 'e':
      case 'E':
        s[i] = '3';
        break;
      case 'i':
      case 'I':
        s[i] = "!|1"[get_random_u8() % 3];
        break;
        /*      case 'k': s[i]='c'; break;
           case 'K': s[i]='C'; break; */
      case 'o':
      case 'O':
        s[i] = '0';
        break;
      case 's':
      case 'S':
        if (s[i + 1] && !isalnum((int) (unsigned char) s[i + 1]))
          s[i] = 'z';
        else
          s[i] = '$';
        break;
      case 'z':
        s[i] = 's';
        break;
      case 'Z':
        s[i] = 'S';
        break;
    } else {
      if (s[i] >= 'A' && s[i] <= 'Z' && (get_random_u8() % 3 == 0)) {
        s[i] += 'a' - 'A';      /* 1/3 chance of lower-case */
      } else if (s[i] >= 'a' && s[i] <= 'z' && (get_random_u8() % 3 == 0)) {
        s[i] -= 'a' - 'A';      /* 1/3 chance of upper-case */
      }
    }
}

/* Remove all "\nSF:" from fingerprints */
static char *xml_sf_convert(const char *str) {
  char *temp = (char *) safe_malloc(strlen(str) + 1);
  char *dst = temp, *src = (char *) str;
  char *ampptr = 0;

  while (*src) {
    if (strncmp(src, "\nSF:", 4) == 0) {
      src += 4;
      continue;
    }
    /* Needed so "&something;" is not truncated midway */
    if (*src == '&') {
      ampptr = dst;
    } else if (*src == ';') {
      ampptr = 0;
    }
    *dst++ = *src++;
  }
  if (ampptr != 0) {
    *ampptr = '\0';
  } else {
    *dst = '\0';
  }
  return temp;
}

// Creates an XML <service> element for the information given in
// serviceDeduction.  This function should only be called if ether
// the service name or the service fingerprint is non-null.
// Returns a pointer to a buffer containing the element,
// you will have to call free on it.
static char *getServiceXMLBuf(struct serviceDeductions *sd) {
  string versionxmlstring = "";
  char rpcbuf[128];
  char confBuf[20];
  char *xml_product = NULL, *xml_version = NULL, *xml_extrainfo = NULL;
  char *xml_hostname = NULL, *xml_ostype = NULL, *xml_devicetype = NULL;
  char *xml_servicefp = NULL, *xml_servicefp_temp = NULL;

  versionxmlstring = "<service name=\"";
  versionxmlstring += sd->name ? sd->name : "unknown";
  versionxmlstring += "\"";
  if (sd->product) {
    xml_product = xml_convert(sd->product);
    versionxmlstring += " product=\"";
    versionxmlstring += xml_product;
    free(xml_product);
    xml_product = NULL;
    versionxmlstring += '\"';
  }

  if (sd->version) {
    xml_version = xml_convert(sd->version);
    versionxmlstring += " version=\"";
    versionxmlstring += xml_version;
    free(xml_version);
    xml_version = NULL;
    versionxmlstring += '\"';
  }

  if (sd->extrainfo) {
    xml_extrainfo = xml_convert(sd->extrainfo);
    versionxmlstring += " extrainfo=\"";
    versionxmlstring += xml_extrainfo;
    free(xml_extrainfo);
    xml_extrainfo = NULL;
    versionxmlstring += '\"';
  }

  if (sd->hostname) {
    xml_hostname = xml_convert(sd->hostname);
    versionxmlstring += " hostname=\"";
    versionxmlstring += xml_hostname;
    free(xml_hostname);
    xml_hostname = NULL;
    versionxmlstring += '\"';
  }

  if (sd->ostype) {
    xml_ostype = xml_convert(sd->ostype);
    versionxmlstring += " ostype=\"";
    versionxmlstring += xml_ostype;
    free(xml_ostype);
    xml_ostype = NULL;
    versionxmlstring += '\"';
  }

  if (sd->devicetype) {
    xml_devicetype = xml_convert(sd->devicetype);
    versionxmlstring += " devicetype=\"";
    versionxmlstring += xml_devicetype;
    free(xml_devicetype);
    xml_devicetype = NULL;
    versionxmlstring += '\"';
  }

  if (sd->service_fp) {
    xml_servicefp_temp = xml_convert(sd->service_fp);
    xml_servicefp = xml_sf_convert(xml_servicefp_temp);
    versionxmlstring += " servicefp=\"";
    versionxmlstring += xml_servicefp;
    free(xml_servicefp_temp);
    xml_servicefp_temp = NULL;
    free(xml_servicefp);
    xml_servicefp = NULL;
    versionxmlstring += '\"';
  }

  if (o.rpcscan && sd->rpc_status == RPC_STATUS_GOOD_PROG) {
    Snprintf(rpcbuf, sizeof(rpcbuf),
             " rpcnum=\"%li\" lowver=\"%i\" highver=\"%i\" proto=\"rpc\"",
             sd->rpc_program, sd->rpc_lowver, sd->rpc_highver);
  } else
    rpcbuf[0] = '\0';

  versionxmlstring += " ";
  versionxmlstring += (sd->service_tunnel == SERVICE_TUNNEL_SSL) ? "tunnel=\"ssl\" " : "";
  versionxmlstring += "method=\"";
  versionxmlstring += (sd->dtype == SERVICE_DETECTION_TABLE) ? "table" : "probed";
  versionxmlstring += "\" conf=\"";
  Snprintf(confBuf, 20, "%i", sd->name_confidence);
  versionxmlstring += confBuf;
  versionxmlstring += "\"";
  versionxmlstring += rpcbuf;
  versionxmlstring += " />";
  return strdup(versionxmlstring.c_str());
}

#ifdef WIN32
/* Display a warning that a device is not Ethernet and so raw sockets
   will be used. The warning is shown only once per unique device name. */
void win32_warn_raw_sockets(const char *devname) {
  static set<string> shown_names;

  if (devname != NULL && shown_names.find(devname) == shown_names.end()) {
    error("WARNING: Using raw sockets because %s is not an ethernet device."
          " This probably won't work on Windows.\n", devname);
    shown_names.insert(devname);
  }
}

/* From tcpip.cc. */
bool DnetName2PcapName(const char *dnetdev, char *pcapdev, int pcapdevlen);

/* Display the mapping from libdnet interface names (like "eth0") to WinPcap
   interface names (like "\Device\NPF_{...}"). This is the same mapping used by
   eth_open and so can help diagnose connection problems.  Additionally display
   WinPcap interface names that are not mapped to by any libdnet name, in other
   words the names of interfaces Nmap has no way of using.*/
static void print_iflist_pcap_mapping(const struct interface_info *iflist,
                                      int numifs) {
  pcap_if_t *pcap_ifs;
  list<const pcap_if_t *> leftover_pcap_ifs;
  list<const pcap_if_t *>::iterator leftover_p;
  int i;

  /* Build a list of "leftover" libpcap interfaces. Initially it contains all
     the interfaces. */
  pcap_ifs = getpcapinterfaces();
  for (const pcap_if_t * p = pcap_ifs; p != NULL; p = p->next)
    leftover_pcap_ifs.push_front(p);

  if (numifs > 0 || !leftover_pcap_ifs.empty()) {
    NmapOutputTable Tbl(1 + numifs + leftover_pcap_ifs.size(), 2);

    Tbl.addItem(0, 0, false, "DEV");
    Tbl.addItem(0, 1, false, "WINDEVICE");

    /* Show the libdnet names and what they map to. */
    for (i = 0; i < numifs; i++) {
      char pcap_name[1024];

      if (DnetName2PcapName(iflist[i].devname, pcap_name, sizeof(pcap_name))) {
        /* We got a name. Remove it from the list of leftovers. */
        list<const pcap_if_t *>::iterator next;
        for (leftover_p = leftover_pcap_ifs.begin();
             leftover_p != leftover_pcap_ifs.end(); leftover_p = next) {
          next = leftover_p;
          next++;
          if (strcmp((*leftover_p)->name, pcap_name) == 0)
            leftover_pcap_ifs.erase(leftover_p);
        }
      } else {
        Strncpy(pcap_name, "<none>", sizeof(pcap_name));
      }

      Tbl.addItem(i + 1, 0, false, iflist[i].devname);
      Tbl.addItem(i + 1, 1, true, pcap_name);
    }

    /* Show the "leftover" libpcap interface names (those without a libdnet
       name that maps to them). */
    for (leftover_p = leftover_pcap_ifs.begin();
         leftover_p != leftover_pcap_ifs.end();
         leftover_p++) {
      Tbl.addItem(i + 1, 0, false, "<none>");
      Tbl.addItem(i + 1, 1, false, (*leftover_p)->name);
      i++;
    }

    log_write(LOG_PLAIN, "%s\n", Tbl.printableTable(NULL));
    log_flush_all();
  }

  pcap_freealldevs(pcap_ifs);
}
#endif

/* Print a detailed list of Nmap interfaces and routes to
   normal/skiddy/stdout output */
int print_iflist(void) {
  int numifs = 0, numroutes = 0;
  struct interface_info *iflist;
  struct sys_route *routes;
  NmapOutputTable *Tbl = NULL;
  iflist = getinterfaces(&numifs);
  int i;
  /* First let's handle interfaces ... */
  if (numifs == 0) {
    log_write(LOG_PLAIN, "INTERFACES: NONE FOUND(!)\n");
  } else {
    int devcol = 0, shortdevcol = 1, ipcol = 2, typecol = 3, upcol = 4, maccol = 5;
    Tbl = new NmapOutputTable(numifs + 1, 6);
    Tbl->addItem(0, devcol, false, "DEV", 3);
    Tbl->addItem(0, shortdevcol, false, "(SHORT)", 7);
    Tbl->addItem(0, ipcol, false, "IP/MASK", 7);
    Tbl->addItem(0, typecol, false, "TYPE", 4);
    Tbl->addItem(0, upcol, false, "UP", 2);
    Tbl->addItem(0, maccol, false, "MAC", 3);
    for (i = 0; i < numifs; i++) {
      Tbl->addItem(i + 1, devcol, false, iflist[i].devfullname);
      Tbl->addItemFormatted(i + 1, shortdevcol, false, "(%s)",
                            iflist[i].devname);
      Tbl->addItemFormatted(i + 1, ipcol, false, "%s/%d",
                            inet_ntop_ez(&(iflist[i].addr), sizeof(iflist[i].addr)),
                            iflist[i].netmask_bits);
      if (iflist[i].device_type == devt_ethernet) {
        Tbl->addItem(i + 1, typecol, false, "ethernet");
        Tbl->addItemFormatted(i + 1, maccol, false,
                              "%02X:%02X:%02X:%02X:%02X:%02X",
                              iflist[i].mac[0], iflist[i].mac[1],
                              iflist[i].mac[2], iflist[i].mac[3],
                              iflist[i].mac[4], iflist[i].mac[5]);
      } else if (iflist[i].device_type == devt_loopback)
        Tbl->addItem(i + 1, typecol, false, "loopback");
      else if (iflist[i].device_type == devt_p2p)
        Tbl->addItem(i + 1, typecol, false, "point2point");
      else
        Tbl->addItem(i + 1, typecol, false, "other");
      Tbl->addItem(i + 1, upcol, false,
                   (iflist[i].device_up ? "up" : "down"));
    }
    log_write(LOG_PLAIN, "************************INTERFACES************************\n");
    log_write(LOG_PLAIN, "%s\n", Tbl->printableTable(NULL));
    log_flush_all();
    delete Tbl;
  }

#ifdef WIN32
  /* Print the libdnet->libpcap interface name mapping. */
  print_iflist_pcap_mapping(iflist, numifs);
#endif

  /* OK -- time to handle routes */
  routes = getsysroutes(&numroutes);
  u32 mask_nbo;
  u16 nbits;
  struct in_addr ia;
  if (numroutes == 0) {
    log_write(LOG_PLAIN, "ROUTES: NONE FOUND(!)\n");
  } else {
    int dstcol = 0, devcol = 1, gwcol = 2;
    Tbl = new NmapOutputTable(numroutes + 1, 3);
    Tbl->addItem(0, dstcol, false, "DST/MASK", 8);
    Tbl->addItem(0, devcol, false, "DEV", 3);
    Tbl->addItem(0, gwcol, false, "GATEWAY", 7);
    for (i = 0; i < numroutes; i++) {
      mask_nbo = htonl(routes[i].netmask);
      addr_mtob(&mask_nbo, sizeof(mask_nbo), &nbits);
      assert(nbits <= 32);
      ia.s_addr = routes[i].dest;
      Tbl->addItemFormatted(i + 1, dstcol, false, "%s/%d", inet_ntoa(ia),
                            nbits);
      Tbl->addItem(i + 1, devcol, false, routes[i].device->devfullname);
      if (routes[i].gw.s_addr != 0)
        Tbl->addItem(i + 1, gwcol, true, inet_ntoa(routes[i].gw));
    }
    log_write(LOG_PLAIN, "**************************ROUTES**************************\n");
    log_write(LOG_PLAIN, "%s\n", Tbl->printableTable(NULL));
    log_flush_all();
    delete Tbl;
  }
  return 0;
}

/* Fills in namebuf (as long as there is space in buflen) with the
   Name nmap normal output will use to describe the port.  This takes
   into account to confidence level, any SSL tunneling, etc.  Truncates
   namebuf to 0 length if there is no room.*/
static void getNmapServiceName(struct serviceDeductions *sd, int state,
                               char *namebuf, int buflen) {
  const char *tunnel_prefix;
  int len;

  if (sd->service_tunnel == SERVICE_TUNNEL_SSL)
    tunnel_prefix = "ssl/";
  else
    tunnel_prefix = "";

  if (sd->name != NULL && strcmp(sd->name, "unknown") != 0) {
    /* The port has a name and the name is not "unknown". How confident are we? */
    if (o.servicescan && state == PORT_OPEN && sd->name_confidence <= 5)
      len = Snprintf(namebuf, buflen, "%s%s?", tunnel_prefix, sd->name);
    else
      len = Snprintf(namebuf, buflen, "%s%s", tunnel_prefix, sd->name);
  } else {
    len = Snprintf(namebuf, buflen, "%sunknown", tunnel_prefix);
  }
  if (len >= buflen || len < 0)
    namebuf[0] = '\0';
}

#ifndef NOLUA
static char *formatScriptOutput(ScriptResult sr) {
  std::string result = std::string(), output = sr.get_output();
  string::size_type pos;
  char *c_result, *c_output = new char[output.length() + 1];
  strncpy(c_output, output.c_str(), output.length() + 1);
  int line = 0;
  std::string line_prfx = "|  ";

  char *token = strtok(c_output, "\n");

  result += line_prfx + sr.get_id() + ": ";

  while (token != NULL) {
    if (line > 0)
      result += line_prfx;
    result += std::string(token) + "\n";
    token = strtok(NULL, "\n");
    line++;
  }

  // fix the last line
  pos = result.rfind(line_prfx);
  result.replace(pos, 3, "|_ ");

  // delete the unwanted trailing newline
  pos = result.rfind("\n");
  if (pos != std::string::npos) {
    result.erase(pos, strlen("\n"));
  }
  c_result = strdup(result.c_str());

  delete[]c_output;
  return c_result;
}
#endif /* NOLUA */

/* Prints the familiar Nmap tabular output showing the "interesting"
   ports found on the machine.  It also handles the Machine/Greppable
   output and the XML output.  It is pretty ugly -- in particular I
   should write helper functions to handle the table creation */
void printportoutput(Target * currenths, PortList * plist) {
  char protocol[MAX_IPPROTOSTRLEN + 1];
  char rpcinfo[64];
  char rpcmachineinfo[64];
  char portinfo[64];
  char grepvers[256];
  char *p;
  char *xmlBuf = NULL;
  const char *state;
  char serviceinfo[64];
  char *name = NULL;
  int i;
  int first = 1;
  struct protoent *proto;
  Port *current;
  char hostname[1200];
  struct serviceDeductions sd;
  NmapOutputTable *Tbl = NULL;
  int portcol = -1;             // port or IP protocol #
  int statecol = -1;            // port/protocol state
  int servicecol = -1;          // service or protocol name
  int versioncol = -1;
  int reasoncol = -1;
  int colno = 0;
  unsigned int rowno;
  int numrows;
  int numignoredports = plist->numIgnoredPorts();

  vector<const char *> saved_servicefps;

  if (o.noportscan)
    return;

  log_write(LOG_XML, "<ports>");
  int prevstate = PORT_UNKNOWN;
  int istate;

  while ((istate = plist->nextIgnoredState(prevstate)) != PORT_UNKNOWN) {
    log_write(LOG_XML, "<extraports state=\"%s\" count=\"%d\">\n",
              statenum2str(istate), plist->getStateCounts(istate));
    print_xml_state_summary(plist, istate);
    log_write(LOG_XML, "</extraports>\n");
    prevstate = istate;
  }

  if (numignoredports == plist->numports) {
    if (numignoredports == 0) {
      log_write(LOG_PLAIN, "0 ports scanned on %s\n",
                currenths->NameIP(hostname, sizeof(hostname)));
    } else {
      log_write(LOG_PLAIN, "%s %d scanned %s on %s %s ",
                (numignoredports == 1) ? "The" : "All", numignoredports,
                (numignoredports == 1) ? "port" : "ports",
                currenths->NameIP(hostname, sizeof(hostname)),
                (numignoredports == 1) ? "is" : "are");
      if (plist->numIgnoredStates() == 1) {
        log_write(LOG_PLAIN, "%s", statenum2str(plist->nextIgnoredState(PORT_UNKNOWN)));
      } else {
        prevstate = PORT_UNKNOWN;
        while ((istate = plist->nextIgnoredState(prevstate)) != PORT_UNKNOWN) {
          if (prevstate != PORT_UNKNOWN)
            log_write(LOG_PLAIN, " or ");
          log_write(LOG_PLAIN, "%s (%d)", statenum2str(istate),
                    plist->getStateCounts(istate));
          prevstate = istate;
        }
      }
      if (o.reason)
        print_state_summary(plist, STATE_REASON_EMPTY);
      log_write(LOG_PLAIN, "\n");
    }

    log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Up",
              currenths->targetipstr(), currenths->HostName());
    log_write(LOG_XML, "</ports>\n");
    return;
  }

  if (o.verbose > 1 || o.debugging) {
    time_t tm_secs, tm_sece;
    struct tm *tm;
    char tbufs[128];
    tm_secs = currenths->StartTime();
    tm_sece = currenths->EndTime();
    tm = localtime(&tm_secs);
    if (strftime(tbufs, sizeof(tbufs), "%Y-%m-%d %H:%M:%S %Z", tm) <= 0)
      fatal("Unable to properly format host start time");

    log_write(LOG_PLAIN, "Scanned at %s for %lds\n",
              tbufs, tm_sece - tm_secs);
  }
  log_write(LOG_MACHINE, "Host: %s (%s)", currenths->targetipstr(),
            currenths->HostName());

  /* Show line like:
     Not shown: 3995 closed ports, 514 filtered ports
     if appropriate (note that states are reverse-sorted by # of ports) */
  prevstate = PORT_UNKNOWN;
  while ((istate = plist->nextIgnoredState(prevstate)) != PORT_UNKNOWN) {
    if (prevstate == PORT_UNKNOWN)
      log_write(LOG_PLAIN, "Not shown: ");
    else
      log_write(LOG_PLAIN, ", ");
    char desc[32];
    if (o.ipprotscan)
      Snprintf(desc, sizeof(desc),
               (plist->getStateCounts(istate) ==
                1) ? "protocol" : "protocols");
    else
      Snprintf(desc, sizeof(desc),
               (plist->getStateCounts(istate) == 1) ? "port" : "ports");
    log_write(LOG_PLAIN, "%d %s %s", plist->getStateCounts(istate),
              statenum2str(istate), desc);
    prevstate = istate;
  }

  if (prevstate != PORT_UNKNOWN)
    log_write(LOG_PLAIN, "\n");

  if (o.reason)
    print_state_summary(plist, STATE_REASON_FULL);

  /* OK, now it is time to deal with the service table ... */
  colno = 0;
  portcol = colno++;
  statecol = colno++;
  servicecol = colno++;
  if (o.reason)
    reasoncol = colno++;
  if (o.servicescan || o.rpcscan)
    versioncol = colno++;

  numrows = plist->numports - numignoredports;

#ifndef NOLUA
  int scriptrows = 0;
  if (plist->numscriptresults > 0)
    scriptrows = plist->numscriptresults;
  numrows += scriptrows;
#endif

  assert(numrows > 0);
  numrows++; // The header counts as a row

  Tbl = new NmapOutputTable(numrows, colno);

  // Lets start with the headers
  if (o.ipprotscan)
    Tbl->addItem(0, portcol, false, "PROTOCOL", 8);
  else
    Tbl->addItem(0, portcol, false, "PORT", 4);
  Tbl->addItem(0, statecol, false, "STATE", 5);
  Tbl->addItem(0, servicecol, false, "SERVICE", 7);
  if (versioncol > 0)
    Tbl->addItem(0, versioncol, false, "VERSION", 7);
  if (reasoncol > 0)
    Tbl->addItem(0, reasoncol, false, "REASON", 6);

  log_write(LOG_MACHINE, "\t%s: ", (o.ipprotscan) ? "Protocols" : "Ports");

  rowno = 1;
  if (o.ipprotscan) {
    current = NULL;
    while ((current = plist->nextPort(current, IPPROTO_IP, 0)) != NULL) {
      if (!plist->isIgnoredState(current->state)) {
        if (!first)
          log_write(LOG_MACHINE, ", ");
        else
          first = 0;
        if (o.reason)
          Tbl->addItem(rowno, reasoncol, true, port_reason_str(current->reason));
        state = statenum2str(current->state);
        proto = nmap_getprotbynum(htons(current->portno));
        Snprintf(portinfo, sizeof(portinfo), "%s", proto ? proto->p_name : "unknown");
        Tbl->addItemFormatted(rowno, portcol, false, "%d", current->portno);
        Tbl->addItem(rowno, statecol, true, state);
        Tbl->addItem(rowno, servicecol, true, portinfo);
        log_write(LOG_MACHINE, "%d/%s/%s/", current->portno, state,
                  (proto) ? proto->p_name : "");
        log_write(LOG_XML, "<port protocol=\"ip\" portid=\"%d\">"
                  "<state state=\"%s\" reason=\"%s\" reason_ttl=\"%d\"",
                  current->portno, state,
                  reason_str(current->reason.reason_id, SINGULAR),
                  current->reason.ttl);

        if (current->reason.ip_addr.s_addr)
          log_write(LOG_XML, " reason_ip=\"%s\"", inet_ntoa(current->reason.ip_addr));
        log_write(LOG_XML, "/>");

        if (proto && proto->p_name && *proto->p_name)
          log_write(LOG_XML, "\n<service name=\"%s\" conf=\"8\" method=\"table\" />", proto->p_name);
        log_write(LOG_XML, "</port>\n");
        rowno++;
      }
    }
  } else {
    current = NULL;
    while ((current = plist->nextPort(current, TCPANDUDPANDSCTP, 0)) != NULL) {
      if (!plist->isIgnoredState(current->state)) {
        if (!first)
          log_write(LOG_MACHINE, ", ");
        else
          first = 0;
        strcpy(protocol, IPPROTO2STR(current->proto));
        Snprintf(portinfo, sizeof(portinfo), "%d/%s", current->portno, protocol);
        state = statenum2str(current->state);
        current->getServiceDeductions(&sd);
        if (sd.service_fp && saved_servicefps.size() <= 8)
          saved_servicefps.push_back(sd.service_fp);

        if (o.rpcscan) {
          switch (sd.rpc_status) {
          case RPC_STATUS_UNTESTED:
            rpcinfo[0] = '\0';
            strcpy(rpcmachineinfo, "");
            break;
          case RPC_STATUS_UNKNOWN:
            strcpy(rpcinfo, "(RPC (Unknown Prog #))");
            strcpy(rpcmachineinfo, "R");
            break;
          case RPC_STATUS_NOT_RPC:
            rpcinfo[0] = '\0';
            strcpy(rpcmachineinfo, "N");
            break;
          case RPC_STATUS_GOOD_PROG:
            name = nmap_getrpcnamebynum(sd.rpc_program);
            Snprintf(rpcmachineinfo, sizeof(rpcmachineinfo),
                     "(%s:%li*%i-%i)", (name) ? name : "", sd.rpc_program,
                     sd.rpc_lowver, sd.rpc_highver);
            if (!name) {
              Snprintf(rpcinfo, sizeof(rpcinfo), "(#%li (unknown) V%i-%i)",
                       sd.rpc_program, sd.rpc_lowver, sd.rpc_highver);
            } else {
              if (sd.rpc_lowver == sd.rpc_highver) {
                Snprintf(rpcinfo, sizeof(rpcinfo), "(%s V%i)", name,
                         sd.rpc_lowver);
              } else
                Snprintf(rpcinfo, sizeof(rpcinfo), "(%s V%i-%i)", name,
                         sd.rpc_lowver, sd.rpc_highver);
            }
            break;
          default:
            fatal("Unknown rpc_status %d", sd.rpc_status);
            break;
          }
          Snprintf(serviceinfo, sizeof(serviceinfo), "%s%s%s",
                   (sd.name) ? sd.name : ((*rpcinfo) ? "" : "unknown"),
                   (sd.name) ? " " : "", rpcinfo);
        } else {
          getNmapServiceName(&sd, current->state, serviceinfo, sizeof(serviceinfo));
          rpcmachineinfo[0] = '\0';
        }
        Tbl->addItem(rowno, portcol, true, portinfo);
        Tbl->addItem(rowno, statecol, false, state);
        Tbl->addItem(rowno, servicecol, true, serviceinfo);
        if (o.reason)
          Tbl->addItem(rowno, reasoncol, true, port_reason_str(current->reason));

        if (*sd.fullversion)
          Tbl->addItem(rowno, versioncol, true, sd.fullversion);

        // How should we escape illegal chars in grepable output?
        // Well, a reasonably clean way would be backslash escapes
        // such as \/ and \\ .  // But that makes it harder to pick
        // out fields with awk, cut, and such.  So I'm gonna use the
        // ugly hat (fitting to grepable output) or replacing the '/'
        // character with '|' in the version field.
        Strncpy(grepvers, sd.fullversion, sizeof(grepvers) / sizeof(*grepvers));
        p = grepvers;
        while ((p = strchr(p, '/'))) {
          *p = '|';
          p++;
        }
        if (!sd.name)
          serviceinfo[0] = '\0';
        else {
          p = serviceinfo;
          while ((p = strchr(p, '/'))) {
            *p = '|';
            p++;
          }
        }
        log_write(LOG_MACHINE, "%d/%s/%s//%s/%s/%s/", current->portno,
                  state, protocol, serviceinfo, rpcmachineinfo, grepvers);

        log_write(LOG_XML, "<port protocol=\"%s\" portid=\"%d\">",
                  protocol, current->portno);
        log_write(LOG_XML, "<state state=\"%s\" reason=\"%s\" reason_ttl=\"%d\"",
                  state, reason_str(current->reason.reason_id, SINGULAR),
                  current->reason.ttl);
        if (current->reason.ip_addr.s_addr)
          log_write(LOG_XML, " reason_ip=\"%s\"", inet_ntoa(current->reason.ip_addr));
        log_write(LOG_XML, "/>");

        if (sd.name || sd.service_fp) {
          xmlBuf = getServiceXMLBuf(&sd);
          if (xmlBuf) {
            log_write(LOG_XML, "%s", xmlBuf);
            free(xmlBuf);
            xmlBuf = NULL;
          }
        }

        rowno++;
#ifndef NOLUA
        if (o.script) {
          ScriptResults::iterator ssr_iter;

          for (ssr_iter = current->scriptResults.begin();
               ssr_iter != current->scriptResults.end(); ssr_iter++) {
            char *xml_id = xml_convert(ssr_iter->get_id().c_str());
            char *xml_scriptoutput =
                xml_convert(ssr_iter->get_output().c_str());
            log_write(LOG_XML, "<script id=\"%s\" output=\"%s\" />",
                      xml_id, xml_scriptoutput);
            free(xml_id);
            free(xml_scriptoutput);

            char *script_output = formatScriptOutput((*ssr_iter));
            Tbl->addItem(rowno, 0, true, true, script_output);
            free(script_output);
            rowno++;
          }

        }
#endif

        log_write(LOG_XML, "</port>\n");
      }
    }

  }
  /*  log_write(LOG_PLAIN,"\n"); */
  /* Grepable output supports only one ignored state. */
  if (plist->numIgnoredStates() == 1) {
    istate = plist->nextIgnoredState(PORT_UNKNOWN);
    if (plist->getStateCounts(istate) > 0)
      log_write(LOG_MACHINE, "\tIgnored State: %s (%d)",
                statenum2str(istate), plist->getStateCounts(istate));
  }
  log_write(LOG_XML, "</ports>\n");

  // Now we write the table for the user
  log_write(LOG_PLAIN, "%s", Tbl->printableTable(NULL));
  delete Tbl;

  // There may be service fingerprints I would like the user to submit
  if (saved_servicefps.size() > 0) {
    int numfps = saved_servicefps.size();
    log_write(LOG_PLAIN, "%d service%s unrecognized despite returning data."
              " If you know the service/version, please submit the following"
              " fingerprint%s at"
              " http://www.insecure.org/cgi-bin/servicefp-submit.cgi :\n",
              numfps, (numfps > 1) ? "s" : "", (numfps > 1) ? "s" : "");
    for (i = 0; i < numfps; i++) {
      if (numfps > 1)
        log_write(LOG_PLAIN, "==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============\n");
      log_write(LOG_PLAIN, "%s\n", saved_servicefps[i]);
    }
  }
  log_flush_all();
}


/* Escape a string for inclusion in XML. This gets <>&, "' for attribute values,
   -- for inside comments, and characters with value > 0x7F. It also gets
   control characters with value < 0x20 to avoid parser normalization of \r\n\t
   in attribute values. If this is not desired in some cases, we'll have to add
   a parameter to control this. */
char *xml_convert(const char *str) {
  /* result is the result buffer; n + 1 is the allocated size. Double the
     allocation when space runs out. */
  char *result = NULL;
  size_t n = 0, len;
  const char *p;
  int i;

  i = 0;
  for (p = str; *p != '\0'; p++) {
    const char *repl;
    char buf[32];

    if (*p == '<')
      repl = "&lt;";
    else if (*p == '>')
      repl = "&gt;";
    else if (*p == '&')
      repl = "&amp;";
    else if (*p == '"')
      repl = "&quot;";
    else if (*p == '\'')
      repl = "&apos;";
    else if (*p == '-' && p > str && *(p - 1) == '-') {
      /* Escape -- for comments. */
      repl = "&#45;";
    } else if (*p < 0x20 || (unsigned char) *p > 0x7F) {
      /* Escape control characters and anything outside of ASCII. We have to
         emit UTF-8 and an easy way to do that is to emit ASCII. */
      Snprintf(buf, sizeof(buf), "&#x%x;", (unsigned char) *p);
      repl = buf;
    } else {
      /* Unescaped character. */
      buf[0] = *p;
      buf[1] = '\0';
      repl = buf;
    }

    len = strlen(repl);
    /* Double the size of the result buffer if necessary. */
    if (i == 0 || i + len > n) {
      n = (i + len) * 2;
      result = (char *) safe_realloc(result, n + 1);
    }
    memcpy(result + i, repl, len);
    i += len;
  }
  /* Trim to length. (Also does initial allocation when str is empty.) */
  result = (char *) safe_realloc(result, i + 1);
  result[i] = '\0';

  return result;
}

char *logfilename(const char *str, struct tm *tm) {
  char *ret, *end, *p;
  char tbuf[10];
  int retlen = strlen(str) * 6 + 1;

  ret = (char *) safe_malloc(retlen);
  end = ret + retlen;

  for (p = ret; *str; str++) {
    if (*str == '%') {
      str++;

      if (!*str)
        break;

      switch (*str) {
      case 'H':
        strftime(tbuf, sizeof tbuf, "%H", tm);
        break;
      case 'M':
        strftime(tbuf, sizeof tbuf, "%M", tm);
        break;
      case 'S':
        strftime(tbuf, sizeof tbuf, "%S", tm);
        break;
      case 'T':
        strftime(tbuf, sizeof tbuf, "%H%M%S", tm);
        break;
      case 'R':
        strftime(tbuf, sizeof tbuf, "%H%M", tm);
        break;
      case 'm':
        strftime(tbuf, sizeof tbuf, "%m", tm);
        break;
      case 'd':
        strftime(tbuf, sizeof tbuf, "%d", tm);
        break;
      case 'y':
        strftime(tbuf, sizeof tbuf, "%y", tm);
        break;
      case 'Y':
        strftime(tbuf, sizeof tbuf, "%Y", tm);
        break;
      case 'D':
        strftime(tbuf, sizeof tbuf, "%m%d%y", tm);
        break;
      default:
        *p++ = *str;
        continue;
      }

      assert(end - p > 1);
      Strncpy(p, tbuf, end - p - 1);
      p += strlen(tbuf);
    } else {
      *p++ = *str;
    }
  }

  *p = 0;

  return (char *) safe_realloc(ret, strlen(ret) + 1);
}

/* This is the workhorse of the logging functions.  Usually it is
   called through log_write(), but it can be called directly if you
   are dealing with a vfprintf-style va_list.  Unlike log_write, YOU
   CAN ONLY CALL THIS WITH ONE LOG TYPE (not a bitmask full of them).
   In addition, YOU MUST SANDWHICH EACH EXECUTION IF THIS CALL BETWEEN
   va_start() AND va_end() calls. */
void log_vwrite(int logt, const char *fmt, va_list ap) {
  static char *writebuf = NULL;
  static int writebuflen = 8192;
  bool skid_noxlate = false;
  int rc = 0;
  int len;
  int fileidx = 0;
  int l;
  va_list apcopy;

  if (!writebuf)
    writebuf = (char *) safe_malloc(writebuflen);

  if (logt == LOG_SKID_NOXLT) {
    logt = LOG_SKID;
    skid_noxlate = true;
  }

  switch (logt) {
  case LOG_STDOUT:
    vfprintf(o.nmap_stdout, fmt, ap);
    break;

  case LOG_STDERR:
    fflush(stdout); // Otherwise some systems will print stderr out of order
    vfprintf(stderr, fmt, ap);
    break;

  case LOG_NORMAL:
  case LOG_MACHINE:
  case LOG_SKID:
  case LOG_XML:
#ifdef WIN32
    apcopy = ap;
#else
    va_copy(apcopy, ap); /* Needed in case we need to do a second vsnprintf */
#endif
    l = logt;
    fileidx = 0;
    while ((l & 1) == 0) {
      fileidx++;
      l >>= 1;
    }
    assert(fileidx < LOG_NUM_FILES);
    if (o.logfd[fileidx]) {
      len = Vsnprintf(writebuf, writebuflen, fmt, ap);
      if (len == 0) {
        va_end(apcopy);
        return;
      } else if (len < 0 || len >= writebuflen) {
        /* Didn't have enough space.  Expand writebuf and try again */
        if (len >= writebuflen) {
          writebuflen = len + 1024;
        } else {
          /* Windows seems to just give -1 rather than the amount of space we
             would need.  So lets just gulp up a huge amount in the hope it
             will be enough */
          writebuflen *= 500;
        }
        writebuf = (char *) safe_realloc(writebuf, writebuflen);
        len = Vsnprintf(writebuf, writebuflen, fmt, apcopy);
        if (len <= 0 || len >= writebuflen) {
          fatal("%s: vsnprintf failed.  Even after increasing bufferlen to %d, Vsnprintf returned %d (logt == %d).  Please report this as a bug to nmap-dev (including this whole error message) as described at http://nmap.org/book/man-bugs.html.  Quitting.", __func__, writebuflen, len, logt);
        }
      }
      if (logt == LOG_SKID && !skid_noxlate)
        skid_output(writebuf);
      rc = fwrite(writebuf, len, 1, o.logfd[fileidx]);
      if (rc != 1) {
        fatal("Failed to write %d bytes of data to (logt==%d) stream. fwrite returned %d.  Quitting.", len, logt, rc);
      }
      va_end(apcopy);
    }
    break;

  default:
    fatal("%s(): Passed unknown log type (%d).  Note that this function, unlike log_write, can only handle one log type at a time (no bitmasks)", __func__, logt);
  }

  return;
}

/* Write some information (printf style args) to the given log stream(s).
 Remember to watch out for format string bugs.  */
void log_write(int logt, const char *fmt, ...) {
  va_list ap;
  assert(logt > 0);

  if (!fmt || !*fmt)
    return;

  for (int l = 1; l <= LOG_MAX; l <<= 1) {
    if (logt & l) {
      va_start(ap, fmt);
      log_vwrite(l, fmt, ap);
      va_end(ap);
    }
  }
  return;
}

/* Close the given log stream(s) */
void log_close(int logt) {
  int i;
  if (logt < 0 || logt > LOG_FILE_MASK)
    return;
  for (i = 0; logt; logt >>= 1, i++)
    if (o.logfd[i] && (logt & 1))
      fclose(o.logfd[i]);
}

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void log_flush(int logt) {
  int i;

  if (logt & LOG_STDOUT) {
    fflush(o.nmap_stdout);
    logt -= LOG_STDOUT;
  }

  if (logt & LOG_STDERR) {
    fflush(stderr);
    logt -= LOG_STDERR;
  }

  if (logt & LOG_SKID_NOXLT)
    fatal("You are not allowed to %s() with LOG_SKID_NOXLT", __func__);

  if (logt < 0 || logt > LOG_FILE_MASK)
    return;

  for (i = 0; logt; logt >>= 1, i++) {
    if (!o.logfd[i] || !(logt & 1))
      continue;
    fflush(o.logfd[i]);
  }

}

/* Flush every single log stream -- all buffered output is written to the
   corresponding logs immediately */
void log_flush_all() {
  int fileno;

  for (fileno = 0; fileno < LOG_NUM_FILES; fileno++) {
    if (o.logfd[fileno])
      fflush(o.logfd[fileno]);
  }
  fflush(stdout);
  fflush(stderr);
}

/* Open a log descriptor of the type given to the filename given.  If
   append is nonzero, the file will be appended instead of clobbered if
   it already exists.  If the file does not exist, it will be created */
int log_open(int logt, int append, char *filename) {
  int i = 0;
  if (logt <= 0 || logt > LOG_FILE_MASK)
    return -1;
  while ((logt & 1) == 0) {
    i++;
    logt >>= 1;
  }
  if (o.logfd[i])
    fatal("Only one %s output filename allowed", logtypes[i]);
  if (*filename == '-' && *(filename + 1) == '\0') {
    o.logfd[i] = stdout;
    o.nmap_stdout = fopen(DEVNULL, "w");
    if (!o.nmap_stdout)
      fatal("Could not assign %s to stdout for writing", DEVNULL);
  } else {
    if (o.append_output)
      o.logfd[i] = fopen(filename, "a");
    else
      o.logfd[i] = fopen(filename, "w");
    if (!o.logfd[i])
      fatal("Failed to open %s output file %s for writing", logtypes[i],
            filename);
  }
  return 1;
}


/* The items in ports should be
   in sequential order for space savings and easier to read output.  Outputs the
   rangelist to the log stream given (such as LOG_MACHINE or LOG_XML) */
static void output_rangelist_given_ports(int logt, unsigned short *ports,
                                         int numports) {
  int i, previous_port = -2, range_start = -2, port;
  char outpbuf[128];

  for (i = 0; i <= numports; i++) {
    port = (i < numports) ? ports[i] : 0xABCDE;
    if (port != previous_port + 1) {
      outpbuf[0] = '\0';
      if (range_start != previous_port && range_start != -2)
        sprintf(outpbuf, "-%hu", previous_port);
      if (port != 0xABCDE) {
        if (range_start != -2)
          strcat(outpbuf, ",");
        sprintf(outpbuf + strlen(outpbuf), "%hu", port);
      }
      if (*outpbuf)
        log_write(logt, "%s", outpbuf);
      range_start = port;
    }
    previous_port = port;
  }
}

/* Output the list of ports scanned to the top of machine parseable
   logs (in a comment, unfortunately).  The items in ports should be
   in sequential order for space savings and easier to read output */
void output_ports_to_machine_parseable_output(struct scan_lists *ports,
                                              int tcpscan, int udpscan,
                                              int sctpscan, int protscan) {
  int tcpportsscanned = ports->tcp_count;
  int udpportsscanned = ports->udp_count;
  int sctpportsscanned = ports->sctp_count;
  int protsscanned = ports->prot_count;
  log_write(LOG_MACHINE, "# Ports scanned: TCP(%d;", tcpportsscanned);
  if (tcpportsscanned)
    output_rangelist_given_ports(LOG_MACHINE, ports->tcp_ports, tcpportsscanned);
  log_write(LOG_MACHINE, ") UDP(%d;", udpportsscanned);
  if (udpportsscanned)
    output_rangelist_given_ports(LOG_MACHINE, ports->udp_ports, udpportsscanned);
  log_write(LOG_MACHINE, ") SCTP(%d;", sctpportsscanned);
  if (sctpportsscanned)
    output_rangelist_given_ports(LOG_MACHINE, ports->sctp_ports, sctpportsscanned);
  log_write(LOG_MACHINE, ") PROTOCOLS(%d;", protsscanned);
  if (protsscanned)
    output_rangelist_given_ports(LOG_MACHINE, ports->prots, protsscanned);
  log_write(LOG_MACHINE, ")\n");
  log_flush_all();
}

// A simple helper function for doscaninfo handles the c14n of o.scanflags
static void doscanflags() {
  struct {
    unsigned char flag;
    const char *name;
  } flags[] = {
    { TH_FIN, "FIN" },
    { TH_SYN, "SYN" },
    { TH_RST, "RST" },
    { TH_PUSH, "PSH" },
    { TH_ACK, "ACK" },
    { TH_URG, "URG" },
    { TH_ECE, "ECE" },
    { TH_CWR, "CWR" }
  };
  if (o.scanflags != -1) {
    log_write(LOG_XML, "scanflags=\"");
    for (unsigned int i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
      if (o.scanflags & flags[i].flag) {
        log_write(LOG_XML, "%s", flags[i].name);
      }
    }
    log_write(LOG_XML, "\"");
  }
}

/* Simple helper function for output_xml_scaninfo_records */
static void doscaninfo(const char *type, const char *proto,
                       unsigned short *ports, int numports) {
  log_write(LOG_XML, "<scaninfo type=\"%s\" ", type);
  if (strncmp(proto, "tcp", 3) == 0) {
    doscanflags();
  }
  log_write(LOG_XML, " protocol=\"%s\" numservices=\"%d\" services=\"",
            proto, numports);
  output_rangelist_given_ports(LOG_XML, ports, numports);
  log_write(LOG_XML, "\" />\n");
}

/* Similar to output_ports_to_machine_parseable_output, this function
   outputs the XML version, which is scaninfo records of each scan
   requested and the ports which it will scan for */
void output_xml_scaninfo_records(struct scan_lists *scanlist) {
  if (o.synscan)
    doscaninfo("syn", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.ackscan)
    doscaninfo("ack", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.bouncescan)
    doscaninfo("bounce", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.connectscan)
    doscaninfo("connect", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.nullscan)
    doscaninfo("null", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.xmasscan)
    doscaninfo("xmas", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.windowscan)
    doscaninfo("window", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.maimonscan)
    doscaninfo("maimon", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.finscan)
    doscaninfo("fin", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.udpscan)
    doscaninfo("udp", "udp", scanlist->udp_ports, scanlist->udp_count);
  if (o.sctpinitscan)
    doscaninfo("sctpinit", "sctp", scanlist->sctp_ports, scanlist->sctp_count);
  if (o.sctpcookieechoscan)
    doscaninfo("sctpcookieecho", "sctp", scanlist->sctp_ports, scanlist->sctp_count);
  if (o.ipprotscan)
    doscaninfo("ipproto", "ip", scanlist->prots, scanlist->prot_count);
  log_flush_all();
}

/* Prints the MAC address (if discovered) to XML output */
static void print_MAC_XML_Info(Target * currenths) {
  const u8 *mac = currenths->MACAddress();
  char macascii[32];
  char vendorstr[128];
  char *xml_mac = NULL;

  if (mac) {
    const char *macvendor = MACPrefix2Corp(mac);
    Snprintf(macascii, sizeof(macascii), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (macvendor) {
      xml_mac = xml_convert(macvendor);
      Snprintf(vendorstr, sizeof(vendorstr), " vendor=\"%s\"", xml_mac);
      free(xml_mac);
    } else
      vendorstr[0] = '\0';
    log_write(LOG_XML, "<address addr=\"%s\" addrtype=\"mac\"%s />\n",
              macascii, vendorstr);
  }
}

/* Helper function to write the status and address/hostname info of a host
   into the XML log */
static void write_xml_initial_hostinfo(Target *currenths,
                                       const char *status) {
  log_write(LOG_XML, "<status state=\"%s\" reason=\"%s\"/>\n", status,
            reason_str(currenths->reason.reason_id, SINGULAR));
  log_write(LOG_XML, "<address addr=\"%s\" addrtype=\"%s\" />\n",
            currenths->targetipstr(), (o.af() == AF_INET) ? "ipv4" : "ipv6");
  print_MAC_XML_Info(currenths);
  /* Output a hostnames element whenever we have a name to write or the target
     is up. */
  if (currenths->TargetName() != NULL || *currenths->HostName() || strcmp(status, "up") == 0) {
    log_write(LOG_XML, "<hostnames>\n");
    if (currenths->TargetName() != NULL) {
      log_write(LOG_XML, "<hostname name=\"%s\" type=\"user\"/>\n",
                currenths->TargetName());
    }
    if (*currenths->HostName()) {
      log_write(LOG_XML, "<hostname name=\"%s\" type=\"PTR\"/>\n",
                currenths->HostName());
    }
    log_write(LOG_XML, "</hostnames>\n");
  }
  log_flush_all();
}

/* Convert a number to a string, keeping the given number of significant digits.
   The result is returned in a static buffer. */
static char *num_to_string_sigdigits(double d, int digits) {
  static char buf[32];
  int shift;
  int n;

  assert(digits >= 0);
  if (d == 0.0) {
    shift = -digits;
  } else {
    shift = (int) floor(log10(fabs(d))) - digits + 1;
    d = floor(d / pow(10.0, shift) + 0.5);
    d = d * pow(10.0, shift);
  }

  n = Snprintf(buf, sizeof(buf), "%.*f", MAX(0, -shift), d);
  assert(n > 0 && n < (int) sizeof(buf));

  return buf;
}
 
/* Writes a heading for a full scan report ("Nmap scan report for..."),
   including host status and DNS records. */
void write_host_header(Target *currenths) {
  if ((currenths->flags & HOST_UP) || o.verbose || o.resolve_all) {
    if (currenths->flags & HOST_UP) {
      log_write(LOG_PLAIN, "Nmap scan report for %s\n", currenths->NameIP());
    } else if (currenths->flags & HOST_DOWN) {
      log_write(LOG_PLAIN, "Nmap scan report for %s [host down", currenths->NameIP());
      if (o.reason)
        log_write(LOG_PLAIN, ", %s", target_reason_str(currenths));
      log_write(LOG_PLAIN, "]\n");
    }
  }
  write_host_status(currenths, o.resolve_all);
  if (currenths->TargetName() != NULL
      && currenths->resolved_addrs.size() > 1) {
    log_write(LOG_PLAIN, "Hostname %s resolves to %u IPs. Only scanned %s\n",
      currenths->TargetName(), (unsigned int) currenths->resolved_addrs.size(),
      currenths->targetipstr());
  }
  /* Print reverse DNS if it differs. */
  if (currenths->TargetName() != NULL
      && currenths->HostName() != NULL && currenths->HostName()[0] != '\0'
      && strcmp(currenths->TargetName(), currenths->HostName()) != 0) {
    log_write(LOG_PLAIN, "rDNS record for %s: %s\n",
      currenths->targetipstr(), currenths->HostName());
  }
}

/* Writes host status info to the log streams (including STDOUT).  An
   example is "Host: 10.11.12.13 (foo.bar.example.com)\tStatus: Up\n" to
   machine log.  resolve_all should be passed nonzero if the user asked
   for all hosts (even down ones) to be resolved */
void write_host_status(Target * currenths, int resolve_all) {
  if (o.listscan) {
    /* write "unknown" to machine and xml */
    log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Unknown\n",
              currenths->targetipstr(), currenths->HostName());
    write_xml_initial_hostinfo(currenths, "unknown");
  } else if (currenths->weird_responses) {
    /* SMURF ADDRESS */
    /* Write xml "down" or "up" based on flags and the smurf info */
    write_xml_initial_hostinfo(currenths,
                               (currenths->
                                flags & HOST_UP) ? "up" : "down");
    log_write(LOG_XML, "<smurf responses=\"%d\" />\n",
              currenths->weird_responses);
    log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Smurf (%d responses)\n",
              currenths->targetipstr(), currenths->HostName(),
              currenths->weird_responses);

    if (o.noportscan) {
      log_write(LOG_PLAIN, "Host seems to be a subnet broadcast address (returned %d extra pings).%s\n",
                currenths->weird_responses,
                (currenths->flags & HOST_UP) ? " Note -- the actual IP also responded." : "");
    } else {
      log_write(LOG_PLAIN, "Host seems to be a subnet broadcast address (returned %d extra pings). %s.\n",
                currenths->weird_responses,
                (currenths->flags & HOST_UP) ? " Still scanning it due to ping response from its own IP" : "Skipping host");
    }
  } else {
    /* Ping scan / port scan. */

    write_xml_initial_hostinfo(currenths, (currenths->flags & HOST_UP) ? "up" : "down");
    if (currenths->flags & HOST_UP) {
      log_write(LOG_PLAIN, "Host is up");
      if (o.reason)
        log_write(LOG_PLAIN, ", %s", target_reason_str(currenths));
      if (currenths->to.srtt != -1)
        log_write(LOG_PLAIN, " (%ss latency)",
                  num_to_string_sigdigits(currenths->to.srtt / 1000000.0, 2));
      log_write(LOG_PLAIN, ".\n");

      log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Up\n",
                currenths->targetipstr(), currenths->HostName());
    } else if (currenths->flags & HOST_DOWN) {
      log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Down\n",
                currenths->targetipstr(), currenths->HostName());
    }
  }
}

/* Returns -1 if adding the entry is not possible because it would
   overflow.  Otherwise it returns the new number of entries.  Note
   that only unique entries are added.  Also note that *numentries is
   incremented if the candidate is added.  arrsize is the number of
   char * members that fit into arr */
static int addtochararrayifnew(char *arr[], int *numentries, int arrsize,
                               char *candidate) {
  int i;

  // First lets see if the member already exists
  for (i = 0; i < *numentries; i++) {
    if (strcmp(arr[i], candidate) == 0)
      return *numentries;
  }

  // Not already there... do we have room for a new one?
  if (*numentries >= arrsize)
    return -1;

  // OK, not already there and we have room, so we'll add it.
  arr[*numentries] = candidate;
  (*numentries)++;
  return *numentries;
}

/* guess is true if we should print guesses */
#define MAX_OS_CLASSMEMBERS 8
static void printosclassificationoutput(const struct
                                        OS_Classification_Results *OSR,
                                        bool guess) {
  int classno, i, familyno;
  int overflow = 0;             /* Whether we have too many devices to list */
  char *types[MAX_OS_CLASSMEMBERS];
  char fullfamily[MAX_OS_CLASSMEMBERS][128];    // "[vendor] [os family]"
  double familyaccuracy[MAX_OS_CLASSMEMBERS];   // highest accuracy for this fullfamily
  char familygenerations[MAX_OS_CLASSMEMBERS][48];      // example: "4.X|5.X|6.X"
  int numtypes = 0, numfamilies = 0;
  char tmpbuf[1024];

  for (i = 0; i < MAX_OS_CLASSMEMBERS; i++) {
    familygenerations[i][0] = '\0';
    familyaccuracy[i] = 0.0;
  }

  if (OSR->overall_results == OSSCAN_SUCCESS) {

    /* Print the OS Classification results to XML output */
    for (classno = 0; classno < OSR->OSC_num_matches; classno++) {
      // Because the OS_Generation filed is optional
      if (OSR->OSC[classno]->OS_Generation) {
        Snprintf(tmpbuf, sizeof(tmpbuf), " osgen=\"%s\"",
                 OSR->OSC[classno]->OS_Generation);
      } else {
        tmpbuf[0] = '\0';
      }
      {
        char *xml_type, *xml_vendor, *xml_class;
        xml_type = xml_convert(OSR->OSC[classno]->Device_Type);
        xml_vendor = xml_convert(OSR->OSC[classno]->OS_Vendor);
        xml_class = xml_convert(OSR->OSC[classno]->OS_Family);
        log_write(LOG_XML,
                  "<osclass type=\"%s\" vendor=\"%s\" osfamily=\"%s\"%s accuracy=\"%d\" />\n",
                  xml_type, xml_vendor, xml_class, tmpbuf,
                  (int) (OSR->OSC_Accuracy[classno] * 100));
        free(xml_type);
        free(xml_vendor);
        free(xml_class);
      }
    }

    // Now to create the fodder for normal output
    for (classno = 0; classno < OSR->OSC_num_matches; classno++) {
      /* We have processed enough if any of the following are true */
      if ((!guess && OSR->OSC_Accuracy[classno] < 1.0) ||
          OSR->OSC_Accuracy[classno] <= OSR->OSC_Accuracy[0] - 0.1 ||
          (OSR->OSC_Accuracy[classno] < 1.0 && classno > 9))
        break;
      if (addtochararrayifnew(types, &numtypes, MAX_OS_CLASSMEMBERS,
                              OSR->OSC[classno]->Device_Type) == -1) {
        overflow = 1;
      }

      // If family and vendor names are the same, no point being redundant
      if (strcmp(OSR->OSC[classno]->OS_Vendor, OSR->OSC[classno]->OS_Family) == 0)
        Strncpy(tmpbuf, OSR->OSC[classno]->OS_Family, sizeof(tmpbuf));
      else
        Snprintf(tmpbuf, sizeof(tmpbuf), "%s %s", OSR->OSC[classno]->OS_Vendor, OSR->OSC[classno]->OS_Family);


      // Let's see if it is already in the array
      for (familyno = 0; familyno < numfamilies; familyno++) {
        if (strcmp(fullfamily[familyno], tmpbuf) == 0) {
          // got a match ... do we need to add the generation?
          if (OSR->OSC[classno]->OS_Generation
              && !strstr(familygenerations[familyno],
                         OSR->OSC[classno]->OS_Generation)) {
            int flen = strlen(familygenerations[familyno]);
            // We add it, preceded by | if something is already there
            if (flen + 2 + strlen(OSR->OSC[classno]->OS_Generation) >=
                sizeof(familygenerations[familyno]))
              fatal("buffer 0verfl0w of familygenerations");
            if (*familygenerations[familyno])
              strcat(familygenerations[familyno], "|");
            strncat(familygenerations[familyno],
                    OSR->OSC[classno]->OS_Generation,
                    sizeof(familygenerations[familyno]) - flen - 1);
          }
          break;
        }
      }

      if (familyno == numfamilies) {
        // Looks like the new family is not in the list yet.  Do we have room to add it?
        if (numfamilies >= MAX_OS_CLASSMEMBERS) {
          overflow = 1;
          break;
        }
        // Have space, time to add...
        Strncpy(fullfamily[numfamilies], tmpbuf, 128);
        if (OSR->OSC[classno]->OS_Generation)
          Strncpy(familygenerations[numfamilies],
                  OSR->OSC[classno]->OS_Generation, 48);
        familyaccuracy[numfamilies] = OSR->OSC_Accuracy[classno];
        numfamilies++;
      }
    }

    if (!overflow && numfamilies >= 1) {
      log_write(LOG_PLAIN, "Device type: ");
      for (classno = 0; classno < numtypes; classno++)
        log_write(LOG_PLAIN, "%s%s", types[classno], (classno < numtypes - 1) ? "|" : "");
      log_write(LOG_PLAIN, "\nRunning%s: ", (familyaccuracy[0] < 1.0) ? " (JUST GUESSING) " : "");
      for (familyno = 0; familyno < numfamilies; familyno++) {
        if (familyno > 0)
          log_write(LOG_PLAIN, ", ");
        log_write(LOG_PLAIN, "%s", fullfamily[familyno]);
        if (*familygenerations[familyno])
          log_write(LOG_PLAIN, " %s", familygenerations[familyno]);
        if (familyaccuracy[familyno] < 1.0)
          log_write(LOG_PLAIN, " (%.f%%)",
                    floor(familyaccuracy[familyno] * 100));
      }
      log_write(LOG_PLAIN, "\n");
    }
  }
  log_flush_all();
  return;
}

/* Prints the MAC address if one was found for the target (generally
   this means that the target is directly connected on an ethernet
   network.  This only prints to human output -- XML is handled by a
   separate call ( print_MAC_XML_Info ) because it needs to be printed
   in a certain place to conform to DTD. */
void printmacinfo(Target * currenths) {
  const u8 *mac = currenths->MACAddress();
  char macascii[32];

  if (mac) {
    const char *macvendor = MACPrefix2Corp(mac);
    Snprintf(macascii, sizeof(macascii), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    log_write(LOG_PLAIN, "MAC Address: %s (%s)\n", macascii,
              macvendor ? macvendor : "Unknown");
  }
}



/* A convenience wrapper around mergeFPs. */
static const char *merge_fpr(const FingerPrintResults * FPR,
                             const Target * currenths,
                             bool isGoodFP, bool wrapit) {
  return mergeFPs(FPR->FPs, FPR->numFPs, isGoodFP, currenths->v4hostip(),
                  currenths->distance,
                  currenths->distance_calculation_method,
                  currenths->MACAddress(), FPR->osscan_opentcpport,
                  FPR->osscan_closedtcpport, FPR->osscan_closedudpport,
                  wrapit);
}

static void write_merged_fpr(const FingerPrintResults * FPR,
                             const Target * currenths,
                             bool isGoodFP, bool wrapit) {
  log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
            "TCP/IP fingerprint:\n%s\n",
            merge_fpr(FPR, currenths, isGoodFP, wrapit));

  /* Added code here to print fingerprint to XML file any time it would be
     printed to any other output format  */
  char *xml_osfp = xml_convert(merge_fpr(FPR, currenths, isGoodFP, wrapit));
  log_write(LOG_XML, "<osfingerprint fingerprint=\"%s\" />\n", xml_osfp);
  free(xml_osfp);
}

/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed).*/
void printosscanoutput(Target * currenths) {
  int i;
  char numlst[512];             /* For creating lists of numbers */
  char *p;                      /* Used in manipulating numlst above */
  FingerPrintResults *FPR;
  int osscan_flag;

  if (!(osscan_flag = currenths->osscanPerformed()))
    return;

  if (currenths->FPR == NULL)
    return;
  FPR = currenths->FPR;

  log_write(LOG_XML, "<os>");
  if (FPR->osscan_opentcpport > 0) {
    log_write(LOG_XML,
              "<portused state=\"open\" proto=\"tcp\" portid=\"%hu\" />\n",
              FPR->osscan_opentcpport);
  }
  if (FPR->osscan_closedtcpport > 0) {
    log_write(LOG_XML,
              "<portused state=\"closed\" proto=\"tcp\" portid=\"%hu\" />\n",
              FPR->osscan_closedtcpport);
  }
  if (FPR->osscan_closedudpport > 0) {
    log_write(LOG_XML,
              "<portused state=\"closed\" proto=\"udp\" portid=\"%hu\" />\n",
              FPR->osscan_closedudpport);
  }

  if (osscan_flag == OS_PERF_UNREL &&
      !(FPR->overall_results == OSSCAN_TOOMANYMATCHES ||
        (FPR->num_perfect_matches > 8 && !o.debugging)))
    log_write(LOG_PLAIN, "Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port\n");

  // If the FP can't be submitted anyway, might as well make a guess.
  const char *reason = FPR->OmitSubmissionFP();
  printosclassificationoutput(FPR->getOSClassification(), o.osscan_guess || reason);

  if (FPR->overall_results == OSSCAN_SUCCESS &&
      (FPR->num_perfect_matches <= 8 || o.debugging)) {
    /* Success, not too many perfect matches. */
    if (FPR->num_perfect_matches > 0) {
      /* Some perfect matches. */
      for (i = 0; FPR->accuracy[i] == 1; i++) {
        char *p;
        log_write(LOG_XML,
                  "<osmatch name=\"%s\" accuracy=\"100\" line=\"%d\" />\n",
                  p = xml_convert(FPR->prints[i]->OS_name),
                  FPR->prints[i]->line);
        free(p);
      }

      log_write(LOG_MACHINE, "\tOS: %s", FPR->prints[0]->OS_name);
      for (i = 1; FPR->accuracy[i] == 1; i++)
        log_write(LOG_MACHINE, "|%s", FPR->prints[i]->OS_name);

      log_write(LOG_PLAIN, "OS details: %s", FPR->prints[0]->OS_name);
      for (i = 1; FPR->accuracy[i] == 1; i++)
        log_write(LOG_PLAIN, ", %s", FPR->prints[i]->OS_name);
      log_write(LOG_PLAIN, "\n");

      if (o.debugging || o.verbose > 1)
        write_merged_fpr(FPR, currenths, reason == NULL, true);
    } else {
      /* No perfect matches. */
      if ((o.verbose > 1 || o.debugging) && reason)
        log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
                  "OS fingerprint not ideal because: %s\n", reason);

      if ((o.osscan_guess || reason) && FPR->num_matches > 0) {
        /* Print the best guesses available */
        for (i = 0; i < 10 && i < FPR->num_matches && FPR->accuracy[i] > FPR->accuracy[0] - 0.10; i++) {
          char *p;
          log_write(LOG_XML,
                    "<osmatch name=\"%s\" accuracy=\"%d\" line=\"%d\"/>\n",
                    p = xml_convert(FPR->prints[i]->OS_name),
                    (int) (FPR->accuracy[i] * 100), FPR->prints[i]->line);
          free(p);
        }

        log_write(LOG_PLAIN, "Aggressive OS guesses: %s (%.f%%)",
                  FPR->prints[0]->OS_name, floor(FPR->accuracy[0] * 100));
        for (i = 1; i < 10 && FPR->num_matches > i && FPR->accuracy[i] > FPR->accuracy[0] - 0.10; i++)
          log_write(LOG_PLAIN, ", %s (%.f%%)", FPR->prints[i]->OS_name, floor(FPR->accuracy[i] * 100));

        log_write(LOG_PLAIN, "\n");
      }

      if (!reason) {
        log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
                  "No exact OS matches for host (If you know what OS is running on it, see http://nmap.org/submit/ ).\n");
        write_merged_fpr(FPR, currenths, true, true);
      } else {
        log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
                  "No exact OS matches for host (test conditions non-ideal).\n");
        if (o.verbose > 1 || o.debugging)
          write_merged_fpr(FPR, currenths, false, false);
      }
    }
  } else if (FPR->overall_results == OSSCAN_NOMATCHES) {
    /* No matches at all. */
    if (!reason) {
      log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
                "No OS matches for host (If you know what OS is running on it, see http://nmap.org/submit/ ).\n");
      write_merged_fpr(FPR, currenths, true, true);
    } else {
      log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
                "OS fingerprint not ideal because: %s\n", reason);
      log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
                "No OS matches for host\n");
      if (o.debugging || o.verbose > 1)
        write_merged_fpr(FPR, currenths, false, false);
    }
  } else if (FPR->overall_results == OSSCAN_TOOMANYMATCHES
             || (FPR->num_perfect_matches > 8 && !o.debugging)) {
    /* Too many perfect matches. */
    log_write(LOG_NORMAL | LOG_SKID_NOXLT | LOG_STDOUT,
              "Too many fingerprints match this host to give specific OS details\n");
    if (o.debugging || o.verbose > 1)
      write_merged_fpr(FPR, currenths, false, false);
  } else {
    assert(0);
  }

  log_write(LOG_XML, "</os>\n");

  if (currenths->seq.lastboot) {
    char tmbuf[128];
    struct timeval tv;
    time_t lastboot;
    lastboot = (time_t) currenths->seq.lastboot;
    strncpy(tmbuf, ctime(&lastboot), sizeof(tmbuf));
    chomp(tmbuf);
    gettimeofday(&tv, NULL);
    if (o.verbose)
      log_write(LOG_PLAIN, "Uptime guess: %.3f days (since %s)\n",
                (double) (tv.tv_sec - currenths->seq.lastboot) / 86400,
                tmbuf);
    log_write(LOG_XML, "<uptime seconds=\"%li\" lastboot=\"%s\" />\n",
              tv.tv_sec - currenths->seq.lastboot, tmbuf);
  }

  if (currenths->distance != -1) {
    log_write(LOG_PLAIN, "Network Distance: %d hop%s\n",
              currenths->distance, (currenths->distance == 1) ? "" : "s");
    log_write(LOG_XML, "<distance value=\"%d\" />\n", currenths->distance);
  }

  if (currenths->seq.responses > 3) {
    p = numlst;
    for (i = 0; i < currenths->seq.responses; i++) {
      if (p - numlst > (int) (sizeof(numlst) - 15))
        fatal("STRANGE ERROR #3877 -- please report to fyodor@insecure.org\n");
      if (p != numlst)
        *p++ = ',';
      sprintf(p, "%X", currenths->seq.seqs[i]);
      while (*p)
        p++;
    }

    log_write(LOG_XML,
              "<tcpsequence index=\"%li\" difficulty=\"%s\" values=\"%s\" />\n",
              (long) currenths->seq.index,
              seqidx2difficultystr(currenths->seq.index), numlst);
    if (o.verbose)
      log_write(LOG_PLAIN, "%s", seqreport(&(currenths->seq)));

    log_write(LOG_MACHINE, "\tSeq Index: %d", currenths->seq.index);
  }

  if (currenths->seq.responses > 2) {
    p = numlst;
    for (i = 0; i < currenths->seq.responses; i++) {
      if (p - numlst > (int) (sizeof(numlst) - 15))
        fatal("STRANGE ERROR #3876 -- please report to fyodor@insecure.org\n");
      if (p != numlst)
        *p++ = ',';
      sprintf(p, "%hX", currenths->seq.ipids[i]);
      while (*p)
        p++;
    }
    log_write(LOG_XML, "<ipidsequence class=\"%s\" values=\"%s\" />\n",
              ipidclass2ascii(currenths->seq.ipid_seqclass), numlst);
    if (o.verbose)
      log_write(LOG_PLAIN, "IP ID Sequence Generation: %s\n",
                ipidclass2ascii(currenths->seq.ipid_seqclass));
    log_write(LOG_MACHINE, "\tIP ID Seq: %s",
              ipidclass2ascii(currenths->seq.ipid_seqclass));

    p = numlst;
    for (i = 0; i < currenths->seq.responses; i++) {
      if (p - numlst > (int) (sizeof(numlst) - 15))
        fatal("STRANGE ERROR #3877 -- please report to fyodor@insecure.org\n");
      if (p != numlst)
        *p++ = ',';
      sprintf(p, "%X", currenths->seq.timestamps[i]);
      while (*p)
        p++;
    }

    log_write(LOG_XML, "<tcptssequence class=\"%s\"",
              tsseqclass2ascii(currenths->seq.ts_seqclass));
    if (currenths->seq.ts_seqclass != TS_SEQ_UNSUPPORTED) {
      log_write(LOG_XML, " values=\"%s\"", numlst);
    }
    log_write(LOG_XML, " />\n");
  }
  log_flush_all();
}

/* An auxillary function for printserviceinfooutput(). Returns
   non-zero if a and b are considered the same hostnames. */
static int hostcmp(const char *a, const char *b) {
  return strcasestr(a, b) ? 1 : 0;
}

/* Prints the alternate hostname/OS/device information we got from the service
   scan (if it was performed) */
void printserviceinfooutput(Target * currenths) {
  Port *p = NULL;
  struct serviceDeductions sd;
  int i, numhostnames = 0, numostypes = 0, numdevicetypes = 0;
  char hostname_tbl[MAX_SERVICE_INFO_FIELDS][MAXHOSTNAMELEN];
  char ostype_tbl[MAX_SERVICE_INFO_FIELDS][64];
  char devicetype_tbl[MAX_SERVICE_INFO_FIELDS][64];
  const char *delim;

  for (i = 0; i < MAX_SERVICE_INFO_FIELDS; i++)
    hostname_tbl[i][0] = ostype_tbl[i][0] = devicetype_tbl[i][0] = '\0';

  while ((p = currenths->ports.nextPort(p, TCPANDUDPANDSCTP, PORT_OPEN))) {
    // The following 2 lines (from portlist.h) tell us that we don't need to
    // worry about free()ing anything in the serviceDeductions struct. pass in
    // an allocated struct serviceDeductions (don't wory about initializing, and
    // you don't have to free any internal ptrs.
    p->getServiceDeductions(&sd);

    if (sd.hostname && !hostcmp(currenths->HostName(), sd.hostname)) {
      for (i = 0; i < MAX_SERVICE_INFO_FIELDS; i++) {
        if (hostname_tbl[i][0] && hostcmp(&hostname_tbl[i][0], sd.hostname))
          break;

        if (!hostname_tbl[i][0]) {
          numhostnames++;
          strncpy(&hostname_tbl[i][0], sd.hostname, sizeof(hostname_tbl[i]));
          break;
        }
      }
    }

    if (sd.ostype) {
      for (i = 0; i < MAX_SERVICE_INFO_FIELDS; i++) {
        if (ostype_tbl[i][0] && !strcmp(&ostype_tbl[i][0], sd.ostype))
          break;

        if (!ostype_tbl[i][0]) {
          numostypes++;
          strncpy(&ostype_tbl[i][0], sd.ostype, sizeof(ostype_tbl[i]));
          break;
        }
      }
    }

    if (sd.devicetype) {
      for (i = 0; i < MAX_SERVICE_INFO_FIELDS; i++) {
        if (devicetype_tbl[i][0] && !strcmp(&devicetype_tbl[i][0], sd.devicetype))
          break;

        if (!devicetype_tbl[i][0]) {
          numdevicetypes++;
          strncpy(&devicetype_tbl[i][0], sd.devicetype, sizeof(devicetype_tbl[i]));
          break;
        }
      }
    }

  }

  if (!numhostnames && !numostypes && !numdevicetypes)
    return;

  log_write(LOG_PLAIN, "Service Info:");

  delim = " ";
  if (numhostnames) {
    log_write(LOG_PLAIN, "%sHost%s: %s", delim, numhostnames == 1 ? "" : "s", &hostname_tbl[0][0]);
    for (i = 1; i < MAX_SERVICE_INFO_FIELDS; i++) {
      if (hostname_tbl[i][0])
        log_write(LOG_PLAIN, ", %s", &hostname_tbl[i][0]);
    }
    delim = "; ";
  }

  if (numostypes) {
    log_write(LOG_PLAIN, "%sOS%s: %s", delim, numostypes == 1 ? "" : "s",
              &ostype_tbl[0][0]);
    for (i = 1; i < MAX_SERVICE_INFO_FIELDS; i++) {
      if (ostype_tbl[i][0])
        log_write(LOG_PLAIN, ", %s", &ostype_tbl[i][0]);
    }
    delim = "; ";
  }

  if (numdevicetypes) {
    log_write(LOG_PLAIN, "%sDevice%s: %s", delim,
              numdevicetypes == 1 ? "" : "s", &devicetype_tbl[0][0]);
    for (i = 1; i < MAX_SERVICE_INFO_FIELDS; i++) {
      if (devicetype_tbl[i][0])
        log_write(LOG_PLAIN, ", %s", &devicetype_tbl[i][0]);
    }
    delim = "; ";
  }

  log_write(LOG_PLAIN, "\n");
  log_flush_all();
}

#ifndef NOLUA
void printhostscriptresults(Target * currenths) {
  ScriptResults::iterator iter;
  char *script_output, *xml_id, *xml_scriptoutput;

  if (currenths->scriptResults.size() > 0) {
    log_write(LOG_XML, "<hostscript>");
    log_write(LOG_PLAIN, "\nHost script results:\n");
    for (iter = currenths->scriptResults.begin();
         iter != currenths->scriptResults.end();
         iter++) {
      xml_id = xml_convert(iter->get_id().c_str());
      xml_scriptoutput = xml_convert(iter->get_output().c_str());
      log_write(LOG_XML, "<script id=\"%s\" output=\"%s\" />",
                xml_id, xml_scriptoutput);
      script_output = formatScriptOutput((*iter));
      log_write(LOG_PLAIN, "%s\n", script_output);
      free(script_output);
      free(xml_id);
      free(xml_scriptoutput);
    }
    log_write(LOG_XML, "</hostscript>");
  }
}
#endif

/* Print a table with traceroute hops. */
static void printtraceroute_normal(Target * currenths) {
  static const int HOP_COL = 0, RTT_COL = 1, HOST_COL = 2;
  NmapOutputTable Tbl(currenths->traceroute_hops.size() + 1, 3);
  struct probespec probe;
  list<TracerouteHop>::iterator it;
  int row;

  /* No trace, must be localhost. */
  if (currenths->traceroute_hops.size() == 0)
    return;

  /* Print header. */
  log_write(LOG_PLAIN, "\n");
  probe = currenths->traceroute_probespec;
  if (probe.type == PS_TCP) {
    log_write(LOG_PLAIN, "TRACEROUTE (using port %d/%s)\n",
              probe.pd.tcp.dport, proto2ascii(probe.proto));
  } else if (probe.type == PS_UDP) {
    log_write(LOG_PLAIN, "TRACEROUTE (using port %d/%s)\n",
              probe.pd.udp.dport, proto2ascii(probe.proto));
  } else if (probe.type == PS_SCTP) {
    log_write(LOG_PLAIN, "TRACEROUTE (using port %d/%s)\n",
              probe.pd.sctp.dport, proto2ascii(probe.proto));
  } else if (probe.type == PS_ICMP || probe.type == PS_PROTO) {
    struct protoent *proto = nmap_getprotbynum(htons(probe.proto));
    log_write(LOG_PLAIN, "TRACEROUTE (using proto %d/%s)\n",
              probe.proto, proto ? proto->p_name : "unknown");
  }

  row = 0;
  Tbl.addItem(row, HOP_COL, false, "HOP");
  Tbl.addItem(row, RTT_COL, false, "RTT");
  Tbl.addItem(row, HOST_COL, false, "ADDRESS");
  row++;

  it = currenths->traceroute_hops.begin();

  if (!o.debugging) {
    /* Consolidate shared hops. */
    TracerouteHop *shared_hop = NULL;
    struct sockaddr_storage addr;
    size_t sslen;

    sslen = sizeof(addr);
    currenths->TargetSockAddr(&addr, &sslen);
    while (it != currenths->traceroute_hops.end()
           && sockaddr_storage_cmp(&it->tag, &addr) != 0) {
      shared_hop = &*it;
      it++;
    }

    if (shared_hop != NULL) {
      Tbl.addItem(row, HOP_COL, false, "-");
      if (shared_hop->ttl == 1) {
        Tbl.addItemFormatted(row, RTT_COL, true,
          "Hop 1 is the same as for %s",
          inet_ntop_ez(&shared_hop->tag, sizeof(shared_hop->tag)));
      } else if (shared_hop->ttl > 1) {
        Tbl.addItemFormatted(row, RTT_COL, true,
          "Hops 1-%d are the same as for %s", shared_hop->ttl,
          inet_ntop_ez(&shared_hop->tag, sizeof(shared_hop->tag)));
      }
      row++;
    }
  }

  while (it != currenths->traceroute_hops.end()) {
    Tbl.addItemFormatted(row, HOP_COL, false, "%d", it->ttl);
    if (it->timedout) {
      if (o.debugging) {
        Tbl.addItem(row, RTT_COL, false, "...");
        it++;
      } else {
        /* The beginning and end of timeout consolidation. */
        int begin_ttl, end_ttl;
        begin_ttl = end_ttl = it->ttl;
        for ( ; it != currenths->traceroute_hops.end() && it->timedout; it++)
          end_ttl = it->ttl;
        if (begin_ttl == end_ttl)
          Tbl.addItem(row, RTT_COL, false, "...");
        else
          Tbl.addItemFormatted(row, RTT_COL, false, "... %d", end_ttl);
      }
      row++;
    } else {
      /* Normal hop output. */
      char namebuf[256];

      it->display_name(namebuf, sizeof(namebuf));
      if (it->rtt < 0)
        Tbl.addItem(row, RTT_COL, false, "--");
      else
        Tbl.addItemFormatted(row, RTT_COL, false, "%.2f ms", it->rtt);
      Tbl.addItemFormatted(row, HOST_COL, false, "%s", namebuf);
      row++;
      it++;
    }
  }

  log_write(LOG_PLAIN, "%s", Tbl.printableTable(NULL));

  log_flush(LOG_PLAIN);
}

static void printtraceroute_xml(Target * currenths) {
  struct probespec probe;
  list<TracerouteHop>::iterator it;

  /* No trace, must be localhost. */
  if (currenths->traceroute_hops.size() == 0)
    return;

  /* XML traceroute header */
  log_write(LOG_XML, "<trace ");
  probe = currenths->traceroute_probespec;
  if (probe.type == PS_TCP) {
    log_write(LOG_XML, "port=\"%d\" proto=\"%s\"",
              probe.pd.tcp.dport, proto2ascii(probe.proto));
  } else if (probe.type == PS_UDP) {
    log_write(LOG_XML, "port=\"%d\" proto=\"%s\"",
              probe.pd.udp.dport, proto2ascii(probe.proto));
  } else if (probe.type == PS_SCTP) {
    log_write(LOG_XML, "port=\"%d\" proto=\"%s\"",
              probe.pd.sctp.dport, proto2ascii(probe.proto));
  } else if (probe.type == PS_ICMP || probe.type == PS_PROTO) {
    struct protoent *proto = nmap_getprotbynum(htons(probe.proto));
    if (proto == NULL)
      log_write(LOG_XML, "proto=\"%d\"", probe.proto);
    else
      log_write(LOG_XML, "proto=\"%s\"", proto->p_name);
  }
  log_write(LOG_XML, ">\n");

  for (it = currenths->traceroute_hops.begin();
       it != currenths->traceroute_hops.end();
       it++) {
    if (it->timedout)
      continue;
    log_write(LOG_XML, "<hop ttl=\"%d\" ipaddr=\"%s\"",
              it->ttl, inet_ntop_ez(&it->addr, sizeof(it->addr)));
    if (it->rtt < 0)
      log_write(LOG_XML, " rtt=\"--\"");
    else
      log_write(LOG_XML, " rtt=\"%.2f\"", it->rtt);
    if (!it->name.empty())
      log_write(LOG_XML, " host=\"%s\"", it->name.c_str());
    log_write(LOG_XML, "/>\n");
  }

  /* traceroute XML footer */
  log_write(LOG_XML, "</trace>\n");
  log_flush(LOG_XML);
}

void printtraceroute(Target * currenths) {
  printtraceroute_normal(currenths);
  printtraceroute_xml(currenths);
}

void printtimes(Target *currenths) {
  if (currenths->to.srtt != -1 || currenths->to.rttvar != -1) {
    if (o.debugging) {
      log_write(LOG_STDOUT, "Final times for host: srtt: %d rttvar: %d  to: %d\n",
        currenths->to.srtt, currenths->to.rttvar, currenths->to.timeout);
    }
    log_write(LOG_XML, "<times srtt=\"%d\" rttvar=\"%d\" to=\"%d\" />\n",
      currenths->to.srtt, currenths->to.rttvar, currenths->to.timeout);
  }
}

/* Prints a status message while the program is running */
void printStatusMessage() {
  // Pre-computations
  struct timeval tv;
  gettimeofday(&tv, NULL);
  int time = (int) (o.TimeSinceStartMS(&tv) / 1000.0);

  log_write(LOG_STDOUT, "Stats: %d:%02d:%02d elapsed; %d hosts completed (%d up), %d undergoing %s\n",
            time / 60 / 60, time / 60 % 60, time % 60, o.numhosts_scanned,
            o.numhosts_up, o.numhosts_scanning,
            scantype2str(o.current_scantype));
}


/* Prints the statistics and other information that goes at the very end
   of an Nmap run */
void printfinaloutput() {
  time_t timep;
  char mytime[128];
  struct timeval tv;
  char statbuf[128];

  gettimeofday(&tv, NULL);
  timep = time(NULL);

  if (o.numhosts_scanned == 0
#ifndef NOLUA
      && o.scriptupdatedb == 0
#endif
      )
    error("WARNING: No targets were specified, so 0 hosts scanned.");
  if (o.numhosts_scanned == 1 && o.numhosts_up == 0 && !o.listscan &&
      o.pingtype != PINGTYPE_NONE)
    log_write(LOG_STDOUT, "Note: Host seems down. If it is really up, but blocking our ping probes, try -PN\n");
  else if (o.numhosts_up > 0) {
    if (o.osscan && o.servicescan)
      log_write(LOG_PLAIN, "OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .\n");
    else if (o.osscan)
      log_write(LOG_PLAIN, "OS detection performed. Please report any incorrect results at http://nmap.org/submit/ .\n");
    else if (o.servicescan)
      log_write(LOG_PLAIN, "Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .\n");
  }

  log_write(LOG_STDOUT | LOG_SKID,
            "Nmap done: %d %s (%d %s up) scanned in %.2f seconds\n",
            o.numhosts_scanned,
            (o.numhosts_scanned == 1) ? "IP address" : "IP addresses",
            o.numhosts_up, (o.numhosts_up == 1) ? "host" : "hosts",
            o.TimeSinceStartMS(&tv) / 1000.0);
  if (o.verbose && o.isr00t && o.RawScan())
    log_write(LOG_STDOUT | LOG_SKID, "           %s\n",
              getFinalPacketStats(statbuf, sizeof(statbuf)));

  Strncpy(mytime, ctime(&timep), sizeof(mytime));
  chomp(mytime);

  log_write(LOG_XML,
            "<runstats><finished time=\"%lu\" timestr=\"%s\" elapsed=\"%.2f\"/><hosts up=\"%d\" down=\"%d\" total=\"%d\" />\n",
            (unsigned long) timep, mytime,
            o.TimeSinceStartMS(&tv) / 1000.0, o.numhosts_up,
            o.numhosts_scanned - o.numhosts_up, o.numhosts_scanned);

  log_write(LOG_XML,
            "<!-- Nmap done at %s; %d %s (%d %s up) scanned in %.2f seconds -->\n",
            mytime, o.numhosts_scanned,
            (o.numhosts_scanned == 1) ? "IP address" : "IP addresses",
            o.numhosts_up, (o.numhosts_up == 1) ? "host" : "hosts",
            o.TimeSinceStartMS(&tv) / 1000.0);
  log_write(LOG_NORMAL | LOG_MACHINE,
            "# Nmap done at %s -- %d %s (%d %s up) scanned in %.2f seconds\n",
            mytime, o.numhosts_scanned,
            (o.numhosts_scanned == 1) ? "IP address" : "IP addresses",
            o.numhosts_up, (o.numhosts_up == 1) ? "host" : "hosts",
            o.TimeSinceStartMS(&tv) / 1000.0);

  log_write(LOG_XML, "</runstats></nmaprun>\n");
  log_flush_all();
}

/* A record consisting of a data file name ("nmap-services", "nmap-os-db",
   etc.), and the directory and file in which is was found. This is a
   broken-down version of what is stored in o.loaded_data_files. It is used in
   printdatafilepaths. */
struct data_file_record {
  std::string data_file;
  std::string dir;
  std::string file;

  /* Compares this record to another. First compare the directory names, then
     compare the file names. */
  bool operator<(const struct data_file_record &other) {
    int cmp;

    cmp = dir.compare(other.dir);
    if (cmp == 0)
      cmp = file.compare(other.file);

    return cmp < 0;
  }
};

/* Prints the names of data files that were loaded and the paths at which they
   were found. */
void printdatafilepaths() {
  std::list<struct data_file_record> df;
  std::list<struct data_file_record>::iterator iter;
  std::map<std::string, std::string>::iterator map_iter;
  std::string dir;
  unsigned int num_dirs;

  /* Copy the elements of o.loaded_data_files (each a (data file, path) pair) to
     a list of data_file_records to make them easier to manipulate. */
  for (map_iter = o.loaded_data_files.begin();
       map_iter != o.loaded_data_files.end(); map_iter++) {
    struct data_file_record r;
    char *s;

    r.data_file = map_iter->first;
    s = path_get_dirname(map_iter->second.c_str());
    if (s == NULL)
      fatal("%s: failed to allocate temporary memory", __func__);
    r.dir = std::string(s);
    free(s);
    s = path_get_basename(map_iter->second.c_str());
    if (s == NULL)
      fatal("%s: failed to allocate temporary memory", __func__);
    r.file = std::string(s);
    free(s);

    df.push_back(r);
  }

  /* Sort the list, first by directory name, then by file name. This ensures
     that records with the same directory name are contiguous. */
  df.sort();

  /* Count the number of distinct directories. Normally we print something only
     if files came from more than one directory. */
  if (df.empty()) {
    num_dirs = 0;
  } else {
    num_dirs = 1;
    iter = df.begin();
    dir = iter->dir;
    for (iter++; iter != df.end(); iter++) {
      if (iter->dir != dir) {
        num_dirs++;
        dir = iter->dir;
      }
    }
  }

  /* Decide what to print out based on the number of distinct directories and
     the verbosity and debugging levels. */
  if (num_dirs == 0) {
    /* If no files were read, print a message only in debugging mode. */
    if (o.debugging > 0)
      log_write(LOG_PLAIN, "No data files read.\n");
  } else if (num_dirs == 1 && o.verbose && !o.debugging) {
    /* If all the files were from the same directory and we're in verbose mode,
       print a brief message unless we are also in debugging mode. */
    log_write(LOG_PLAIN, "Read data files from: %s\n", dir.c_str());
  } else if ((num_dirs == 1 && o.debugging) || num_dirs > 1) {
    /* If files were read from more than one directory, or if they were read
       from one directory and we are in debugging mode, display all the files
       grouped by directory. */
    iter = df.begin();
    while (iter != df.end()) {
      dir = iter->dir;
      /* Write the directory name. */
      log_write(LOG_PLAIN, "Read from %s:", dir.c_str());
      /* Write files in that directory on the same line. */
      while (iter != df.end() && iter->dir == dir) {
        log_write(LOG_PLAIN, " %s", iter->file.c_str());
        iter++;
      }
      log_write(LOG_PLAIN, ".\n");
    }
  }
}
