
/***************************************************************************
 * ArgParser.cc -- The ArgParser Class is the one in charge of command line*
 * argument parsing. Essentially it contains method parseArguments() that  *
 * takes the usual argc and *argv[] parameters and fills the general       *
 * NpingOps class with all the information needed for the execution of     *
 * Nping.                                                                  *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2014 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

#include "nping.h"

#include "ArgParser.h"
#include "NpingOps.h"
#include "common.h"
#include "nbase.h"
#include "utils.h"
#include "utils_net.h"
#include "output.h"
#include <vector>
using namespace std;

extern NpingOps o;


ArgParser::ArgParser() {

} /* End of ArgParser constructor */



ArgParser::~ArgParser() {

} /* End of ArgParser destructor */



int ArgParser::parseArguments(int argc, char *argv[]) {
  int arg=0;
  int auxint=0;
  long l=0;
  int option_index=0;
  IPAddress aux_ip4;
  struct in_addr auxinaddr;
  u32 aux32=0;
  u16 aux16=0;
  u8 aux8=0;
  u8 auxmac[6];
  u8 *auxbuff=NULL;
  u16 *portlist=NULL;
  char errstr[256];

  struct option long_options[] =  {

  /* Probe modes */
  {"tcp-connect", no_argument, 0, 0},
  {"tcp", no_argument, 0, 0},
  {"udp", no_argument, 0, 0},
  {"icmp", no_argument, 0, 0},
  {"arp", no_argument, 0, 0},
  {"tr", no_argument, 0, 0},
  {"traceroute", no_argument, 0, 0},

  /* Mode shortcuts */
  {"echo-request", no_argument, 0, 0},
  {"destination-unreachable", no_argument, 0, 0},
  {"dest-unr", no_argument, 0, 0},
  {"timestamp", no_argument, 0, 0},
  {"timestamp-request", no_argument, 0, 0},
  {"information", no_argument, 0, 0},
  {"information-request", no_argument, 0, 0},
  {"netmask", no_argument, 0, 0},
  {"netmask-request", no_argument, 0, 0},
  {"arp-request", no_argument, 0, 0},
  {"arp-reply", no_argument, 0, 0},
  {"rarp-request", no_argument, 0, 0},
  {"rarp-reply", no_argument, 0, 0},

   /* TCP/UDP */
  {"source-port", required_argument, 0, 'g'},
  {"dest-port", required_argument, 0, 'p'},
  {"seq", required_argument, 0, 0},
  {"flags", required_argument, 0, 0},
  {"ack", required_argument, 0, 0},
  {"win", required_argument, 0, 0},
  {"csum", required_argument, 0, 0},
  {"badsum", no_argument, 0, 0},

  /* ICMP */
  {"icmp-type", required_argument, 0, 0},
  {"icmp-code", required_argument, 0, 0},
  {"icmp-id", required_argument, 0, 0},
  {"icmp-seq", required_argument, 0, 0},
  {"icmp-redirect-addr", required_argument, 0, 0},
  {"icmp-param-pointer", required_argument, 0, 0},
  {"icmp-advert-lifetime", required_argument, 0, 0},
  {"icmp-advert-entry", required_argument, 0, 0},
  {"icmp-orig-time", required_argument, 0, 0},
  {"icmp-recv-time", required_argument, 0, 0},
  {"icmp-trans-time", required_argument, 0, 0},
  /* TODO: Add relevant flags for different ICMP options */

  /* ARP/RARP */
  /* 1) ARP operation codes. */
  {"arp-type",  required_argument, 0, 0},
  {"rarp-type",  required_argument, 0, 0},
  {"arp-code",  required_argument, 0, 0},
  {"rarp-code",  required_argument, 0, 0},
  {"arp-operation",  required_argument, 0, 0},
  {"arp-op",  required_argument, 0, 0},
  {"rarp-operation",  required_argument, 0, 0},
  {"rarp-op",  required_argument, 0, 0},
  /* 2) Rest of the fields */
  {"arp-sender-mac", required_argument, 0, 0},
  {"arp-sender-ip", required_argument, 0, 0},
  {"arp-target-mac", required_argument, 0, 0},
  {"arp-target-ip", required_argument, 0, 0},
  {"rarp-sender-mac", required_argument, 0, 0},
  {"rarp-sender-ip", required_argument, 0, 0},
  {"rarp-target-mac", required_argument, 0, 0},
  {"rarp-target-ip", required_argument, 0, 0},

  /* Ethernet */
  {"dest-mac", required_argument, 0, 0},
  {"source-mac", required_argument, 0, 0},
  {"spoof-mac", required_argument, 0, 0},
  {"ethertype", required_argument, 0, 0},
  {"ethtype", required_argument, 0, 0},
  {"ether-type", required_argument, 0, 0},

  /* IPv4 */
  {"IPv4", no_argument, 0, '4'},
  {"ipv4", no_argument, 0, '4'},
  {"source-ip", required_argument, 0, 'S'},
  {"dest-ip", required_argument, 0, 0},
  {"tos", required_argument, 0, 0},
  {"id", required_argument, 0, 0},
  {"rf", no_argument, 0, 0},
  {"df", no_argument, 0, 0},
  {"mf", no_argument, 0, 0},
  {"ttl", required_argument, 0, 0},
  {"fragoff", required_argument, 0, 0},
  {"csum-ip", required_argument, 0, 0},
  {"badsum-ip", no_argument, 0, 0},
  {"ip-options", required_argument, 0, 0},
  {"mtu", required_argument, 0, 0},
  {"ip-proto", required_argument, 0, 0},
  /* Remember also: "-f" : Fragment packets*/

  /* IPv6 */
  {"IPv6", no_argument, 0, '6'},
  {"ipv6", no_argument, 0, '6'},
  {"hop-limit", required_argument, 0, 0},
  {"tc", required_argument, 0, 0},
  {"traffic-class", required_argument, 0, 0},
  {"flow", required_argument, 0, 0},

  /* Payload */
  {"data", required_argument, 0, 0},
  {"data-length", required_argument, 0, 0},
  {"data-string", required_argument, 0, 0},

  /* Echo client/server */
  {"echo-client", required_argument, 0, 0},
  {"ec", required_argument, 0, 0},
  {"echo-server", required_argument, 0, 0},
  {"es", required_argument, 0, 0},
  {"echo-port", required_argument, 0, 0},
  {"ep", required_argument, 0, 0},
  {"no-crypto", no_argument, 0, 0},
  {"nc", no_argument, 0, 0},
  {"once", no_argument, 0, 0},
  {"safe-payloads", no_argument, 0, 0},
  {"include-payloads", no_argument, 0, 0},

  /* Timing and performance */
  {"delay", required_argument, 0, 0},
  {"rate", required_argument, 0, 0},

  /* Misc */
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'V'},
  {"count", required_argument, 0, 'c'},
  {"interface", required_argument, 0, 'e'},
  {"privileged", no_argument, 0, 0},
  {"unprivileged", no_argument, 0, 0},
  {"send-eth", no_argument, 0, 0},
  {"send-ip", no_argument, 0, 0},
  {"bpf-filter", required_argument, 0, 0},
  {"filter", required_argument, 0, 0},
  {"nsock-engine", required_argument, 0, 0},
  {"no-capture", no_argument, 0, 'N'},
  {"hide-sent", no_argument, 0, 'H'},

  /* Output */
  {"verbose", optional_argument, 0, 'v'},
  {"reduce-verbosity", optional_argument, 0, 'q'},
  {"debug", no_argument, 0, 0},
  {"quiet", no_argument, 0, 0},
  {0, 0, 0, 0}
  };

  if( argc <= 1 ){
    this->printUsage();
    exit(1);
  }

  /* Let's get this parsing party started */
  while((arg = getopt_long_only(argc,argv,"46c:d::e:fg:hHK:NP:q::p:S:Vv::", long_options, &option_index)) != EOF) {

   aux8=aux16=aux32=auxinaddr.s_addr=0;
   aux_ip4.reset();

   switch(arg) {

   case 0:

/* PROBE MODES ***************************************************************/
    if (optcmp(long_options[option_index].name, "tcp-connect") == 0) {
      o.addMode(DO_TCP_CONNECT);
    }else if (optcmp(long_options[option_index].name, "tcp") == 0) {
      o.addMode(DO_TCP);
    }else if (optcmp(long_options[option_index].name, "udp") == 0) {
      o.addMode(DO_UDP);
    }else if (optcmp(long_options[option_index].name, "icmp") == 0) {
      o.addMode(DO_ICMP);
    }else if (optcmp(long_options[option_index].name, "arp") == 0) {
      o.addMode(DO_ARP);
    }else if (optcmp(long_options[option_index].name, "traceroute") == 0 ||
               optcmp(long_options[option_index].name, "tr") == 0) {
      o.addMode(DO_TRACEROUTE);


/* TCP/UDP OPTIONS ***********************************************************/
    /* TCP Sequence number */
    } else if (optcmp(long_options[option_index].name, "seq") == 0) {
      if ( parse_u32(optarg, &aux32) != OP_SUCCESS )
        nping_fatal(QT_3, "Invalid TCP Sequence number. Value must be 0<=N<2^32.");
      else
        o.tcp.seq.setConstant(aux32);
    /* TCP Flags */
    }else if (optcmp(long_options[option_index].name, "flags") == 0) {
      /* CASE 1: User is a freak and supplied a numeric value directly */
      /* We initially parse it as an u32 so we give the proper error
       * for values like 0x100. */
      if ( parse_u32(optarg, &aux32) == OP_SUCCESS ){
        if( meansRandom(optarg) ){
          o.tcp.flags.setConstant(get_random_u8());
        }else if(aux32>255){
          nping_fatal(QT_3, "Invalid TCP flag specification. Numerical values must be in the range [0,255].");
        }else{
          o.tcp.flags.setConstant((u8)aux32);
        }

      /* CASE 2: User supplied a list of flags in the format "syn,ack,ecn" */
      }else if( contains(optarg, ",") ){
        if( ((strlen(optarg)+1)%4)  !=0 )
          nping_fatal(QT_3, "Invalid format in --flag. Make sure you specify a comma-separed list that contains 3-charater flag names (e.g: --flags syn,ack,psh)");
        aux8=0;
        for(size_t f=0; f< strlen(optarg); f+=4 ){
          if(     !strncasecmp((optarg+f), "CWR",3)){ aux8 = aux8 | 0x80; }
          else if(!strncasecmp((optarg+f), "ECN",3)){ aux8 = aux8 | 0x40; }
          else if(!strncasecmp((optarg+f), "ECE",3)){ aux8 = aux8 | 0x40; }
          else if(!strncasecmp((optarg+f), "URG",3)){ aux8 = aux8 | 0x20; }
          else if(!strncasecmp((optarg+f), "ACK",3)){ aux8 = aux8 | 0x10; }
          else if(!strncasecmp((optarg+f), "PSH",3)){ aux8 = aux8 | 0x08; }
          else if(!strncasecmp((optarg+f), "RST",3)){ aux8 = aux8 | 0x04; }
          else if(!strncasecmp((optarg+f), "SYN",3)){ aux8 = aux8 | 0x02; }
          else if(!strncasecmp((optarg+f), "FIN",3)){ aux8 = aux8 | 0x01; }
          else if(!strncasecmp((optarg+f), "ALL",3)){ aux8=0xFF;  }
          else if(!strncasecmp((optarg+f), "NIL",3)){ aux8=0x00;  }
          else{
            char wrongopt[4];
            memcpy(wrongopt, (optarg+f), 3);
            wrongopt[3]='\0';
            nping_fatal(QT_3, "Invalid TCP flag specification: \"%s\"", wrongopt);
          }
        }
        o.tcp.flags.setConstant(aux8);

      /* CASE 3: User supplied flag initials in format "XYZ..."  */
      }else{
        bool flag3_ok=false;
        /* SPECIAL CASE: User entered exactly 3 chars so we don't know if
         * only one flag was entered or three flags in format "XYZ..." */
        if( strlen(optarg) == 3 ){
          if(     !strcasecmp(optarg, "CWR")){ o.tcp.flags.setConstant(0x80); flag3_ok=true; }
          else if(!strcasecmp(optarg, "ECN")){ o.tcp.flags.setConstant(0x40); flag3_ok=true; }
          else if(!strcasecmp(optarg, "ECE")){ o.tcp.flags.setConstant(0x40); flag3_ok=true; }
          else if(!strcasecmp(optarg, "URG")){ o.tcp.flags.setConstant(0x20); flag3_ok=true; }
          else if(!strcasecmp(optarg, "ACK")){ o.tcp.flags.setConstant(0x10); flag3_ok=true; }
          else if(!strcasecmp(optarg, "PSH")){ o.tcp.flags.setConstant(0x08); flag3_ok=true; }
          else if(!strcasecmp(optarg, "RST")){ o.tcp.flags.setConstant(0x04); flag3_ok=true; }
          else if(!strcasecmp(optarg, "SYN")){ o.tcp.flags.setConstant(0x02); flag3_ok=true; }
          else if(!strcasecmp(optarg, "FIN")){ o.tcp.flags.setConstant(0x01); flag3_ok=true; }
          else if(!strcasecmp(optarg, "ALL")){ o.tcp.flags.setConstant(0xFF); flag3_ok=true; }
          else if(!strcasecmp(optarg, "NIL")){ o.tcp.flags.setConstant(0x00); flag3_ok=true; }
          else{
            flag3_ok=false;
          }
        /* SPECIAL CASE: User supplied an empty string */
        }else if( strlen(optarg) == 0 ){
          o.tcp.flags.setConstant(0x00);
        /* SPECIAL CASE: User supplied special flag "NONE" */
        }else if(!strcasecmp(optarg, "NONE") ){
          o.tcp.flags.setConstant(0x00);
          flag3_ok=true;
        }

        /* User definitely supplied flag initials in format "XYZ..."*/
        if(flag3_ok==false){
          aux8=0;
          for(size_t f=0; f<strlen(optarg); f++){
            switch(optarg[f]){
              case 'C': case 'c': aux8 = aux8 | 0x80; break;
              case 'E': case 'e': aux8 = aux8 | 0x40; break;
              case 'U': case 'u': aux8 = aux8 | 0x20; break;
              case 'A': case 'a': aux8 = aux8 | 0x10; break;
              case 'P': case 'p': aux8 = aux8 | 0x08; break;
              case 'R': case 'r': aux8 = aux8 | 0x04; break;
              case 'S': case 's': aux8 = aux8 | 0x02; break;
              case 'F': case 'f': aux8 = aux8 | 0x01; break;
              default:
                if( isdigit(optarg[f]) )
                  nping_fatal(QT_3, "Invalid TCP flag supplied (%c). If you want to specify flags using a number you must add prefix \"0x\"", optarg[f]);
                else
                  nping_fatal(QT_3, "Invalid TCP flag supplied: %c", optarg[f]);
            }
          }
          o.tcp.flags.setConstant(aux8);
        }
      }
    /* TCP Acknowledgement number */
    } else if (optcmp(long_options[option_index].name, "ack") == 0) {
      if ( parse_u32(optarg, &aux32) != OP_SUCCESS )
        nping_fatal(QT_3, "Invalid TCP ACK number. Value must be 0<=N<2^32.");
      else
        o.tcp.ack.setConstant(aux32);
    /* TCP Window size */
    } else if (optcmp(long_options[option_index].name, "win") == 0) {
      if ( parse_u16(optarg, &aux16) != OP_SUCCESS )
        nping_fatal(QT_3, "Invalid TCP Window size. Value must be 0<=N<65535.");
      else
        o.tcp.win.setConstant(aux16);

/* ICMP OPTIONS **************************************************************/
    /* ICMP Type */
    } else if (optcmp(long_options[option_index].name, "icmp-type") == 0) {
      o.addMode(DO_ICMP);
      /* User may have supplied type as a number */
      if(parse_u8(optarg, &aux8) == OP_SUCCESS){
        o.icmp4.type.setConstant(aux8);
      /* Or maybe the supplied arg is a string that we can recognize */
      }else if(atoICMPType(optarg, &aux8) == OP_SUCCESS){
        o.icmp4.type.setConstant(aux8);
      /* Looks like user supplied a bogus value */
      }else{
        nping_fatal(QT_3, "Invalid ICMP Type. Value must be 0<=N<=255.");
      }
      /* Warn if ICMP Type is not RFC-compliant */
      if( !isICMPType(aux8) )
        nping_warning(QT_1, "Warning: Specified ICMP type (%d) is not RFC compliant.", aux8);
    /* ICMP Code */
    } else if (optcmp(long_options[option_index].name, "icmp-code") == 0) {
      o.addMode(DO_ICMP);
      /* User may have supplied code as a number */
      if(parse_u8(optarg, &aux8) == OP_SUCCESS){
        o.icmp4.code.setConstant(aux8);
      /* Or maybe the supplied arg is a string that we can recognize */
      }else if(atoICMPCode(optarg, &aux8) == OP_SUCCESS){
        o.icmp4.code.setConstant(aux8);
      /* Looks like user supplied a bogus value */
      }else{
        nping_fatal(QT_3, "Invalid ICMP Code. Value must be 0<=N<=255.");
      }
    /* ICMP Identification field */
    } else if (optcmp(long_options[option_index].name, "icmp-id") == 0) {
      o.addMode(DO_ICMP);
      if(parse_u16(optarg, &aux16) == OP_SUCCESS){
        o.icmp4.id.setConstant(aux16);
      }else{
        nping_fatal(QT_3, "Invalid ICMP Identifier. Value must be 0<=N<2^16.");
      }
    /* ICMP Sequence number */
    } else if (optcmp(long_options[option_index].name, "icmp-seq") == 0) {
      o.addMode(DO_ICMP);
      if(parse_u16(optarg, &aux16) == OP_SUCCESS){
        o.icmp4.seq.setConstant(aux16);
      }else{
        nping_fatal(QT_3, "Invalid ICMP Sequence number. Value must be 0<=N<2^16.");
      }
    /* ICMP Redirect Address */
    } else if (optcmp(long_options[option_index].name, "icmp-redirect-addr") == 0) {
      o.addMode(DO_ICMP);
      if(meansRandom(optarg)){
        o.icmp4.redir_addr.setBehavior(FIELD_TYPE_RANDOM);
      }else{
        if(aux_ip4.setIPv4Address(optarg) != OP_SUCCESS){
          nping_fatal(QT_3, "Could not resolve specified ICMP Redirect Address.");
        }else{
          o.icmp4.redir_addr.setConstant(aux_ip4.getIPv4Address());
        }
      }
    /* ICMP Parameter problem pointer */
    } else if (optcmp(long_options[option_index].name, "icmp-param-pointer") == 0) {
      o.addMode(DO_ICMP);
      if(parse_u8(optarg, &aux8) == OP_SUCCESS){
        o.icmp4.pointer.setConstant(aux8);
      }else{
        nping_fatal(QT_3, "Invalid ICMP Parameter problem pointer. Value must be 0<=N<=255..");
      }
    /* ICMP Router Advertisement lifetime */
    } else if (optcmp(long_options[option_index].name, "icmp-advert-lifetime") == 0) {
      o.addMode(DO_ICMP);
      if(parse_u16(optarg, &aux16) == OP_SUCCESS){
        o.icmp4.lifetime.setConstant(aux16);
      }else{
        nping_fatal(QT_3, "Invalid ICMP Router advertisement lifetime. Value must be 0<=N<2^16..");
      }
    /* ICMP Router Advertisement entry */
    } else if (optcmp(long_options[option_index].name, "icmp-advert-entry") == 0) {
      o.addMode(DO_ICMP);
      /* Format should be "IPADDR,PREF":  "192.168.10.99,31337" */
      if( meansRandom(optarg) ){
        while( (auxinaddr.s_addr=get_random_u32()) == 0);
        o.addICMPAdvertEntry( auxinaddr, get_random_u32() );
      }else{
        parseAdvertEntry(optarg, &auxinaddr, &aux32); /* fatal()s on error */
        o.addICMPAdvertEntry(auxinaddr, aux32);
      }
    /* ICMP Timestamp originate timestamp */
    } else if (optcmp(long_options[option_index].name, "icmp-orig-time") == 0) {
      o.addMode(DO_ICMP);
      this->parseICMPTimestamp(optarg, &aux32);
      o.icmp4.ts_orig.setConstant(aux32);
    /* ICMP Timestamp receive timestamp */
    } else if (optcmp(long_options[option_index].name, "icmp-recv-time") == 0) {
      o.addMode(DO_ICMP);
      this->parseICMPTimestamp(optarg, &aux32);
      o.icmp4.ts_rx.setConstant(aux32);
    /* ICMP Timestamp transmit timestamp */
    } else if (optcmp(long_options[option_index].name, "icmp-trans-time") == 0) {
      o.addMode(DO_ICMP);
      this->parseICMPTimestamp(optarg, &aux32);
      o.icmp4.ts_tx.setConstant(aux32);
    /* TODO: Add more relevant flags for different ICMP options */


/* ARP/RARP OPTIONS **********************************************************/
    /* Operation code */
    } else if (optcmp(long_options[option_index].name, "arp-type") == 0 ||
               optcmp(long_options[option_index].name, "rarp-type") == 0 ||
               optcmp(long_options[option_index].name, "arp-code") == 0 ||
               optcmp(long_options[option_index].name, "rarp-code") == 0 ||
               optcmp(long_options[option_index].name, "arp-operation") == 0 ||
               optcmp(long_options[option_index].name, "arp-op") == 0 ||
               optcmp(long_options[option_index].name, "rarp-operation") == 0 ||
               optcmp(long_options[option_index].name, "rarp-op") == 0 ){
        o.addMode(DO_ARP);
        if( atoARPOpCode(optarg, &aux16) != OP_SUCCESS ){
            nping_fatal(QT_3, "Invalid ARP type/operation code");
        }else{
            o.setARPOpCode(aux16);
        }
    /* ARP Sender MAC Address */
    } else if (optcmp(long_options[option_index].name, "arp-sender-mac") == 0 ||
               optcmp(long_options[option_index].name, "rarp-sender-mac") == 0 ){
        if ( parseMAC(optarg, auxmac) != OP_SUCCESS ){
            nping_fatal(QT_3, "Invalid ARP Sender MAC address.");
        }else{
            o.setARPSenderHwAddr(auxmac);
        }
    /* ARP Sender IP Address */
    } else if (optcmp(long_options[option_index].name, "arp-sender-ip") == 0 ||
               optcmp(long_options[option_index].name, "rarp-sender-ip") == 0 ){
        if ( aux_ip4.setIPv4Address(optarg)!=OP_SUCCESS ){
            nping_fatal(QT_3, "Invalid ARP Sender IP address.");
        }else{
            o.setARPSenderProtoAddr(aux_ip4.getIPv4Address());
        }
    /* ARP Target MAC Address */
    } else if (optcmp(long_options[option_index].name, "arp-target-mac") == 0 ||
               optcmp(long_options[option_index].name, "rarp-target-mac") == 0 ){
        if ( parseMAC(optarg, auxmac) != OP_SUCCESS ){
            nping_fatal(QT_3, "Invalid ARP Target MAC address.");
        }else{
            o.setARPTargetHwAddr(auxmac);
        }
    /* ARP Target IP Address */
    } else if (optcmp(long_options[option_index].name, "arp-target-ip") == 0 ||
               optcmp(long_options[option_index].name, "rarp-target-ip") == 0 ){
        if ( aux_ip4.setIPv4Address(optarg)!=OP_SUCCESS ){
            nping_fatal(QT_3, "Invalid ARP Target IP address.");
        }else{
            o.setARPTargetProtoAddr(aux_ip4.getIPv4Address());
        }


/* ETHERNET OPTIONS **********************************************************/
    /* Destination MAC address */
    } else if (optcmp(long_options[option_index].name, "dest-mac") == 0 ){
        if ( parseMAC(optarg, auxmac) != OP_SUCCESS ){
            nping_fatal(QT_3, "Invalid Ethernet Destination MAC address.");
        }else{
            o.setDestMAC(auxmac);
        }
        if( !o.issetSendPreference() )
            o.setSendPreference(PACKET_SEND_ETH_STRONG);
    /* Source MAC address */
    } else if (optcmp(long_options[option_index].name, "source-mac") == 0 ||
               optcmp(long_options[option_index].name, "spoof-mac") == 0 ){
        if ( parseMAC(optarg, auxmac) != OP_SUCCESS ){
            nping_fatal(QT_3, "Invalid Ethernet Source MAC address.");
        }else{
            o.setSourceMAC(auxmac);
        }
        if( !o.issetSendPreference() )
            o.setSendPreference(PACKET_SEND_ETH_STRONG);
    /* Ethernet type field */
    } else if (optcmp(long_options[option_index].name, "ethertype") == 0 ||
               optcmp(long_options[option_index].name, "ethtype") == 0 ||
               optcmp(long_options[option_index].name, "ether-type") == 0 ){
        if ( parse_u16(optarg, &aux16) == OP_SUCCESS ){
            o.setEtherType(aux16);
        }else if ( atoEtherType(optarg, &aux16) == OP_SUCCESS ){
            o.setEtherType(aux16);
        }else{
            nping_fatal(QT_3, "Invalid Ethernet Type.");
        }
        if( !o.issetSendPreference() )
            o.setSendPreference(PACKET_SEND_ETH_STRONG);


/* IPv4 OPTIONS **************************************************************/
    /* Destination IP address. This is just another way to specify targets,
     * provided for consistency with the rest of the parameters. */
    }else if (optcmp(long_options[option_index].name, "dest-ip") == 0 ){
        o.addTargetSpec( strdup(optarg) );
    /* IP Type of service*/
    }else if (optcmp(long_options[option_index].name, "tos") == 0 ){
      if(o.ipv6()){
        nping_fatal(QT_3, "Type of Service (--tos) can only be used in IPv4.");
      }else if( parse_u8(optarg, &aux8)!=OP_SUCCESS){
        nping_fatal(QT_3,"TOS option must be a number between 0 and 255 (inclusive)");
      }else{
        o.ip4.tos.setConstant(aux8);
      }
    /* IP Identification field */
    }else if (optcmp(long_options[option_index].name, "id") == 0 ){
      if(o.ipv6()){
        nping_fatal(QT_3, "Identification (--id) can only be used in IPv4.");
      }else if ( parse_u16(optarg, &aux16)!=OP_SUCCESS){
        nping_fatal(QT_3,"Identification must be a number between 0 and 65535 (inclusive)");
      }else{
        o.ip4.id.setConstant(aux16);
      }
    }else if (optcmp(long_options[option_index].name, "rf") == 0 ){
      o.ip4.rf.setConstant(true);
    /* Don't fragment bit */
    }else if (optcmp(long_options[option_index].name, "df") == 0 ){
      o.ip4.df.setConstant(true);
    /* More fragments bit */
    } else if (optcmp(long_options[option_index].name, "mf") == 0 ){
      o.ip4.mf.setConstant(true);
    /* Time to live (hop-limit in IPv6) */
    } else if (optcmp(long_options[option_index].name, "ttl") == 0  || optcmp(long_options[option_index].name, "hop-limit") == 0 ){
      if (parse_u8(optarg, &aux8)!=OP_SUCCESS){
        nping_fatal(QT_3,"TTL/Hop Limit must be a number between 0 and 255 (inclusive)");
      }else{
        if(o.ipv6()){
          //o.ip6.hlim.setConstant(aux8); // TODO: Finish this!!
        }else{
          o.ip4.ttl.setConstant(aux8);
        }
      }
      /* TODO: At some point we may want to let users specify TTLs like "linux",
       * "bsd" etc, so the default TTL for those systems is used. Check
       * http://members.cox.net/~ndav1/self_published/TTL_values.html
       * for more information */
    /* Fragment offset */
    } else if (optcmp(long_options[option_index].name, "fragoff") == 0 ){
      if(parse_u16(optarg, &aux16)!=OP_SUCCESS){
        nping_fatal(QT_3,"Fragment offset must be a number between 0 and 8191 (inclusive)");
      }else if(aux16>8191){
        nping_fatal(QT_3, "Fragment offset cannot exceed 8191.");
      }else{
        o.ip4.off.setConstant(aux16);
      }
    /* IP checksum */
    } else if (optcmp(long_options[option_index].name, "csum-ip") == 0 ){
      if(parse_u16(optarg, &aux16)!=OP_SUCCESS){
        nping_fatal(QT_3,"The IP checksum must be a number between 0 65535 (inclusive)");
      }else{
        o.ip4.csum.setConstant(aux16);
      }
    /* Set up a bad IP checksum */
    } else if (optcmp(long_options[option_index].name, "badsum-ip") == 0 ){
      o.ip4.csum.setBehavior(FIELD_TYPE_BADSUM);
    /* IP Options */
    } else if (optcmp(long_options[option_index].name, "ip-options") == 0 ){
        /* We need to know if options specification is correct so we perform
         * a little test here, instead of waiting until the IPv4Header
         * complains and fatal()s we just call parse_ip_options() ourselves.
         * The call should fatal if something is wrong with user-supplied opts */
         int foo=0, bar=0;
         u8 buffer[128];
         if( parse_ip_options(optarg, buffer, 128, &foo, &bar, errstr, sizeof(errstr)) < 0 )
            nping_fatal(QT_3, "Incorrect IP options specification.");
         /* If we get here it's safe to store the options */
         o.setIPOptions(optarg);
    /* Maximum Transmission Unit */
    } else if (optcmp(long_options[option_index].name, "mtu") == 0 ){
        /* Special treatment for random here since the generated number must be n%8==0 */
        if(!strcasecmp("rand", optarg) || !strcasecmp("random", optarg)){
            aux16=get_random_u16(); /* We limit the random mtu to a max of 65535 */
            /* Make sure generated number is multiple of 8, adding a few units */
            if(aux16 > 8 )
                aux16-=(aux16%8);
            else
                aux16+=(8-(aux16%8));
            o.setMTU(aux16);
        }else if ( (parse_u32(optarg, &aux32)==OP_SUCCESS) && aux32!=0 && aux32%8==0){
            o.setMTU(aux32);
        }else{
            nping_fatal(QT_3,"MTU must be >0 and multiple of 8");
        }
    } else if (optcmp(long_options[option_index].name, "ip-proto") == 0 ){
        if ( parse_u8(optarg, &aux8) == OP_SUCCESS )
          o.setIPProto(aux8);
        else
          nping_fatal(QT_3,"Protocol number must be a number between 0 and 255 (inclusive)");


/* IPv6 OPTIONS **************************************************************/
    /* IPv6 Traffic class */
    } else if (optcmp(long_options[option_index].name, "traffic-class") == 0 ||
               optcmp(long_options[option_index].name, "tc") == 0 ){
        if ( parse_u8(optarg, &aux8) == OP_SUCCESS )
           o.setTrafficClass(aux8);
        else
            nping_fatal(QT_3,"IPv6 Traffic Class must be a number between 0 and 255 (inclusive)");
    /* IPv6 Flow label */
    } else if (optcmp(long_options[option_index].name, "flow") == 0 ){
		if( meansRandom(optarg) ){
            o.setFlowLabel( get_random_u32()%1048575 ); /* Mod 2^20 so it doesn't exceed 20bits */
        }else if ( parse_u32(optarg, &aux32) == OP_SUCCESS ){
            if( aux32>1048575 )
				nping_fatal(QT_3, "IPv6 Flow Label cannot be greater than 1048575 ");
            else
                o.setFlowLabel(aux32);
        }else{
            nping_fatal(QT_3,"IPv6 Flow Label must be a number between 0 and 1048575");
        }


/* PACKET PAYLOAD OPTIONS  ***************************************************/
    /* Hexadecimal payload specification */
    } else if (optcmp(long_options[option_index].name, "data") == 0 ){
        o.setPayloadType(PL_HEX);
        u8 *tempbuff=NULL;
        size_t len=0;
        if( (tempbuff=parseBufferSpec(optarg, &len))==NULL)
            nping_fatal(QT_3,"Invalid hex string specification\n");
        else{
            u8 *buff = (u8 *) safe_malloc(len);
            memcpy(buff, tempbuff, len);
            o.setPayloadBuffer(buff, len);
        }
    /* Random payload */
    } else if (optcmp(long_options[option_index].name, "data-length") == 0 ){
        o.setPayloadType(PL_RAND);
        if( meansRandom(optarg) ){
            /* We do not generate more than Ethernet standard MTU */
            aux32 = 1 + get_random_u16() % (MAX_RANDOM_PAYLOAD-1);
        }else if ( parse_u32(optarg, &aux32) != OP_SUCCESS  ){
            nping_fatal(QT_3,"Invalid payload length specification");
        }
        if ( aux32 > MAX_PAYLOAD_ALLOWED )
            nping_fatal(QT_3,"data-length must be a value between 0 and %d.", MAX_PAYLOAD_ALLOWED);
        if ( aux32 > MAX_RECOMMENDED_PAYLOAD )
            nping_print(QT_3, "WARNING: Payload exceeds maximum recommended payload (%d)", MAX_RECOMMENDED_PAYLOAD);

        /* Allocate a buffer big enough to hold the desired payload */
        if( (auxbuff=(u8 *)safe_malloc(aux32)) == NULL )
             nping_fatal(QT_3,"Not enough memory to store payload.");
        /* Generate random data and store the payload */
        get_random_bytes(auxbuff, aux32);
        o.setPayloadBuffer(auxbuff, aux32);
    /* ASCII string payload */
    } else if (optcmp(long_options[option_index].name, "data-string") == 0 ){
        o.setPayloadType(PL_STRING);
        int plen=strlen(optarg);
        if ( plen>MAX_PAYLOAD_ALLOWED )
            nping_fatal(QT_3,"data-string must be between 0 and %d characters.", MAX_PAYLOAD_ALLOWED);
        if ( plen > MAX_RECOMMENDED_PAYLOAD )
            nping_print(QT_3, "WARNING: Payload exceeds maximum recommended payload (%d)", MAX_RECOMMENDED_PAYLOAD);
        if( meansRandom(optarg) ){
             auxbuff=(u8*)strdup(getRandomTextPayload());
             plen=strlen((char*)auxbuff);
        }else {
            auxbuff=(u8*)safe_zalloc(plen);
            memcpy(auxbuff, optarg, plen);
        }
        o.setPayloadBuffer((u8*)auxbuff, plen);


/* ECHO C/S MODE OPTIONS *****************************************************/
    } else if (optcmp(long_options[option_index].name, "echo-client")==0 ||
               optcmp(long_options[option_index].name, "ec")==0 ){
        o.setRole(ROLE_CLIENT);
        o.setEchoPassphrase(optarg);
    } else if (optcmp(long_options[option_index].name, "echo-server")==0 ||
               optcmp(long_options[option_index].name, "es")==0 ){
        o.setRole(ROLE_SERVER);
        o.setEchoPassphrase(optarg);
    } else if (optcmp(long_options[option_index].name, "echo-port")==0 ||
               optcmp(long_options[option_index].name, "ep")==0 ){
        if ( parse_u16(optarg, &aux16) == OP_SUCCESS ){
            if(aux16==0)
                nping_fatal(QT_3, "Invalid echo port. Port can't be zero.");
            else
                o.setEchoPort( aux16 );
        }else{
            nping_fatal(QT_3, "Invalid echo port. Value must be 0<N<2^16.");
        }
    } else if (optcmp(long_options[option_index].name, "once")==0 ){
        o.setOnce(true);
    } else if (optcmp(long_options[option_index].name, "no-crypto")==0 ||
               optcmp(long_options[option_index].name, "nc")==0 ){
        o.doCrypto(false);
    } else if (optcmp(long_options[option_index].name, "safe-payloads")==0 ){
        o.echoPayload(false);
    } else if (optcmp(long_options[option_index].name, "include-payloads")==0 ){
        o.echoPayload(true);


/* TIMING AND PERFORMANCE OPTIONS ********************************************/
    /* Inter-packet delay */
    } else if (optcmp(long_options[option_index].name, "delay") == 0 ){
        if ( (l= tval2msecs(optarg)) == -1)
            nping_fatal(QT_3,"Invalid delay supplied. Delay must be a valid, positive integer or floating point number.");
        else if(l<0)
            nping_fatal(QT_3,"Invalid delay supplied. Delays can never be negative.");
        if (l >= 10 * 1000 && tval_unit(optarg) == NULL)
            nping_fatal(QT_3,"Since April 2010, the default unit for --delay is seconds, so your time of \"%s\" is %g seconds. Use \"%sms\" for %g milliseconds.", optarg, l / 1000.0, optarg, l / 1000.0);
        o.setDelay(l);
    /* Tx rate */
    } else if (optcmp(long_options[option_index].name, "rate") == 0 ){
        if (parse_u32(optarg, &aux32)==OP_SUCCESS){
            if(aux32==0){
                nping_fatal(QT_3,"Invalid rate supplied. Rate can never be zero.");
            }else{
                /* Compute delay from rate: delay= 1000ms/rate*/
                aux32 = 1000 / aux32;
                o.setDelay(aux32);
            }
        }else{
            nping_fatal(QT_3,"Invalid rate supplied. Rate must be a valid, positive integer");
        }

/* MISC OPTIONS **************************************************************/
    /* Use a bad checksum for protocols above the network layer */
    } else if (optcmp(long_options[option_index].name, "badsum") == 0) {
      o.tcp.csum.setBehavior(FIELD_TYPE_BADSUM);
      //o.udp.csum.setBehavior(FIELD_TYPE_BADSUM);
      o.icmp4.csum.setBehavior(FIELD_TYPE_BADSUM);
      //o.icmp6.csum.setBehavior(FIELD_TYPE_BADSUM);
      // TODO @todo Uncomment these when UDP and ICMPv6 are implemented
    } else if (optcmp(long_options[option_index].name, "csum") == 0 ){
      if(parse_u16(optarg, &aux16) == OP_SUCCESS){
        o.tcp.csum.setConstant(aux16);
        //o.udp.csum.setConstant(aux16);
        o.icmp4.csum.setConstant(aux16);
        //o.icmp6.csum.setConstant(aux16);
        // TODO @todo Uncomment these when UDP and ICMPv6 are implemented
      }else{
        nping_fatal(QT_3, "Invalid ICMP Identifier. Value must be 0<=N<2^16.");
      }
    } else if (optcmp(long_options[option_index].name, "privileged") == 0 ){
        o.setIsRoot();
    } else if (optcmp(long_options[option_index].name, "unprivileged") == 0 ){
        o.setIsRoot(0);
    } else if (optcmp(long_options[option_index].name, "send-eth") == 0 ){
        o.setSendPreference(PACKET_SEND_ETH_STRONG);
    } else if (optcmp(long_options[option_index].name, "send-ip") == 0 ){
        o.setSendPreference(PACKET_SEND_IP_STRONG);
    } else if (optcmp(long_options[option_index].name, "bpf-filter") == 0 || optcmp(long_options[option_index].name, "filter") == 0){
        o.setBPFFilterSpec( optarg );
        if( o.issetDisablePacketCapture() && o.disablePacketCapture()==true )
            nping_warning(QT_2, "Warning: There is no point on specifying a BPF filter if you disable packet capture. BPF filter will be ignored.");
    } else if (optcmp(long_options[option_index].name, "nsock-engine") == 0){
        if (nsock_set_default_engine(optarg) < 0)
          nping_fatal(QT_3, "Unknown or non-available engine: %s", optarg);
    /* Output Options */
    } else if (optcmp(long_options[option_index].name, "quiet") == 0 ){
            o.setVerbosity(-4);
            o.setDebugging(0);
    }else if (optcmp(long_options[option_index].name, "debug") == 0 ){
            o.setVerbosity(4);
            o.setDebugging(9);
    }

    /* Copy and paste these to add more options. */
    //}else if (optcmp(long_options[option_index].name, "") == 0 ){
    //} else if (optcmp(long_options[option_index].name, "") == 0 ){

    break; /* case 0 */


/* OPTIONS THAT CAN BE SPECIFIED AS A SINGLE CHARACTER ***********************/

    case '4': /* IPv4 */
      o.setAddressFamily(AF_INET);
    break; /* case '4': */

    case '6': /* IPv6 */
      o.setAddressFamily(AF_INET6);
    break; /* case '6': */

    case 'f': /* Fragment packets */
        if( o.issetMTU() == true ){
            nping_warning(QT_3,"WARNING: -f is irrelevant if an MTU has been previously specified");
        }
        else{
            nping_print(DBG_1, "Setting default MTU=%d", DEFAULT_MTU_FOR_FRAGMENTATION);
            o.setMTU( DEFAULT_MTU_FOR_FRAGMENTATION );
        }
    break;

    case 'g': /* Source port */
        /* Parse port spec */
        spec_to_ports(optarg, &portlist, &auxint);
        if( portlist == NULL || auxint <= 0 ){
          nping_fatal(QT_3,"Invalid source port specification.");
        }else{
          o.setSourcePorts(portlist, auxint);
          o.tcp.sport.setDiscreteSet(portlist, (u32)auxint);
        }
    break; /* case 'g': */

    case 'p': /* Destination port */
        /* Parse port spec */
        spec_to_ports(optarg, &portlist, &auxint);
        if( portlist == NULL || auxint <= 0 ){
          nping_fatal(QT_3,"Invalid target ports specification.");
        }else{
          o.setTargetPorts(portlist, auxint);
          o.tcp.dport.setDiscreteSet(portlist, (u32)auxint);
        }
    break; /* case 'p': */

    case 'S': /* Source/Spoof IP address */
        /* IPv6 */
        if( o.ipv6() ){
          /* Set random address */
          if( meansRandom(optarg) ){
            struct in6_addr ipv6addr;
            for(int i6=0; i6<16; i6++)
               ipv6addr.s6_addr[i6]=get_random_u8();
            aux_ip4.setAddress(ipv6addr);
            o.setSpoofAddress(aux_ip4);
          }
          /* Set user supplied address (if we manage to resolve it) */
          else{
            if(aux_ip4.setIPv6Address(optarg)!=OP_SUCCESS){
              nping_fatal(QT_3, "Could not resolve source IPv6 address.");
            }else{
              o.setSpoofAddress(aux_ip4);
            }
          }
        /* IPv4 */
        }else{
          if( meansRandom(optarg) ){
            while ( (auxinaddr.s_addr=get_random_u32()) == 0 );
            aux_ip4.setAddress(auxinaddr);
            o.setSpoofAddress(aux_ip4);
          }else{
             if( aux_ip4.setIPv4Address(optarg)!=OP_SUCCESS){
               nping_fatal(QT_3, "Could not resolve source IPv4 address.");
             }else{
               o.setSpoofAddress(aux_ip4);
             }
          }
        }
    break; /* case 'S': */

    case '?':
        printUsage();
        exit(1);
    break; /* case 'h': */

    case 'h': /* Help */
        printUsage();
        exit(0);
    break; /* case 'h': */

    case 'V': /* Version */
        printVersion();
        exit(0);
    break; /* case 'V': */

    case 'c': /* Packet rounds */
      if( meansRandom(optarg) ){
        o.setRounds( get_random_u32()%1024 );
      }else if( parse_u32(optarg, &aux32) == OP_SUCCESS ){
        o.setRounds(aux32);
      }else{
        nping_fatal(QT_3,"Packet rounds must be an integer greater than 0.");
      }
    break; /* case 'c': */

    case 'e': /* Network interface */
        if(strlen(optarg)==0)
            nping_fatal(QT_3,"Invalid network interface supplied. Interface name cannot be NULL.");
        else
            o.setDevice( strdup(optarg) );
    break; /* case 'e': */

    case 'N': /* Don't capture packets */
        o.setDisablePacketCapture(true);
        if( o.issetBPFFilterSpec() )
            nping_warning(QT_2, "Warning: A custom BPF filter was specified before disabling packet capture. BPF filter will be ignored.");
    break; /* case 'N': */

    case 'H': /* Hide sent packets */
        o.setShowSentPackets(false);
    break; /* case 'H': */

    case 'd': /* Debug mode */
      if (optarg){
        if (isdigit(optarg[0]) || optarg[0]=='-'){
            auxint = strtol( optarg, NULL, 10);
            if ( ((auxint==0) && (optarg[0] != '0')) || auxint<0 || auxint > 9)
                nping_fatal(QT_3,"Debugging level must be an integer between 0 and 9.");
            else{
                o.setDebugging( auxint );
                /* When user specifies a debugging level, if no verbosity was specified,
                * increase it automatically. If user specified a verbosity level, then leave
                * it like it was. */
                if(o.issetVerbosity()==false)
                    o.setVerbosity( (auxint>4) ? 4 : auxint );
            }
        }else {
            const char *p;
            o.increaseVerbosity();
            o.increaseDebugging();
            for (p = optarg != NULL ? optarg : ""; *p == 'd'; p++){
                o.increaseVerbosity();
                o.increaseDebugging();
            }
            if (*p != '\0')
                nping_fatal(QT_3,"Invalid argument to -d: \"%s\".", optarg);
        }
    }else{
        o.increaseVerbosity();
        o.increaseDebugging();
    }
    break; /* case 'd': */

    case 'v': /* Verbosity */
      if (optarg){
        if (isdigit(optarg[0]) || optarg[0]=='-'){
            auxint = strtol( optarg, NULL, 10);
            if ( ((auxint==0) && (optarg[0] != '0')) || auxint<(-4) || auxint > 4)
                nping_fatal(QT_3,"Verbosity level must be an integer between -4 and +4.");
            else
                o.setVerbosity( auxint );
        }else {
            const char *p;
            o.increaseVerbosity();
            for (p = optarg != NULL ? optarg : ""; *p == 'v'; p++)
                o.increaseVerbosity();
            if (*p != '\0')
                nping_fatal(QT_3,"Invalid argument to -v: \"%s\".", optarg);
        }
    }else{
        o.increaseVerbosity();
    }
    break; /* case 'v': */

    case 'q': /* Reduce verbosity */
      if (optarg){
        if (isdigit(optarg[0])){
            auxint = strtol( optarg, NULL, 10);
            if ( ((auxint==0) && (optarg[0] != '0')) || auxint<0 || auxint > 4)
                nping_fatal(QT_3,"You can only reduce verbosity from level 0 to level -4.");
            else
                o.setVerbosity( -auxint );
        }else {
            const char *p;
            o.decreaseVerbosity();
            for (p = optarg != NULL ? optarg : ""; *p == 'q'; p++)
                o.decreaseVerbosity();
            if (*p != '\0')
                nping_fatal(QT_3,"Invalid argument to -q: \"%s\".", optarg);
        }
    }else{
        o.decreaseVerbosity();
    }
    break; /* case 'q': */

  } /* End of switch */

 } /* End of getopt while */


 /* Now it's time to parse target host specifications. As nmap does, Nping
  * treats everything getopt() can't parse as a host specification. At this
  * point, var optind should point to the argv[] position that contains the
  * first unparsed argument. User may specify multiple target hosts so to
  * handle this, function grab_next_host_spec() returns the next target
  * specification available. This function will be called until there are no
  * more target hosts to parse (returned NULL). Once we have a spec, we use
  * class NpingTargets, that stores the specs and will provide the targets
  * through calls to getNextTarget();
  * */
  const char *next_spec=NULL;
  while ( (next_spec= grab_next_host_spec(NULL, false, argc, argv)) != NULL ){
    o.addTargetSpec(next_spec);
  }
  return OP_SUCCESS;
} /* End of parseArguments() */




/** Prints version information to stdout */
void ArgParser::printVersion(void){
  printf("\n%s version %s ( %s )\n",  NPING_NAME, NPING_VERSION, NPING_URL);
  return;
} /* End of printVersion() */



/** Prints usage information to stdout */
void ArgParser::printUsage(void){

  printf("%s %s ( %s )\n"
"Usage: nping [Probe mode] [Options] {target specification}\n"
"\n"
"TARGET SPECIFICATION:\n"
"  Targets may be specified as hostnames, IP addresses, networks, etc.\n"
"  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.*.1-24\n"
"PROBE MODES:\n"
"  --tcp-connect                    : Unprivileged TCP connect probe mode.\n"
"  --tcp                            : TCP probe mode.\n"
"  --udp                            : UDP probe mode.\n"
"  --icmp                           : ICMP probe mode.\n"
"  --arp                            : ARP/RARP probe mode.\n"
"  --tr, --traceroute               : Traceroute mode (can only be used with \n"
"                                     TCP/UDP/ICMP modes).\n"
"TCP CONNECT MODE:\n"
"   -p, --dest-port <port spec>     : Set destination port(s).\n"
"   -g, --source-port <portnumber>  : Try to use a custom source port.\n"
"TCP PROBE MODE:\n"
"   -g, --source-port <portnumber>  : Set source port.\n"
"   -p, --dest-port <port spec>     : Set destination port(s).\n"
"   --seq <seqnumber>               : Set sequence number.\n"
"   --flags <flag list>             : Set TCP flags (ACK,PSH,RST,SYN,FIN...)\n"
"   --ack <acknumber>               : Set ACK number.\n"
"   --win <size>                    : Set window size.\n"
"   --csum <sum>                    : Set a fixed checksum.\n"
"   --badsum                        : Use a random invalid checksum. \n"
"UDP PROBE MODE:\n"
"   -g, --source-port <portnumber>  : Set source port.\n"
"   -p, --dest-port <port spec>     : Set destination port(s).\n"
"   --csum <sum>                    : Set a fixed checksum.\n"
"   --badsum                        : Use a random invalid checksum. \n"
"ICMP PROBE MODE:\n"
"  --icmp-type <type>               : ICMP type.\n"
"  --icmp-code <code>               : ICMP code.\n"
"  --icmp-id <id>                   : Set identifier.\n"
"  --icmp-seq <n>                   : Set sequence number.\n"
"  --icmp-redirect-addr <addr>      : Set redirect address.\n"
"  --icmp-param-pointer <pnt>       : Set parameter problem pointer.\n"
"  --icmp-advert-lifetime <time>    : Set router advertisement lifetime.\n"
"  --icmp-advert-entry <IP,pref>    : Add router advertisement entry.\n"
"  --icmp-orig-time  <timestamp>    : Set originate timestamp.\n"
"  --icmp-recv-time  <timestamp>    : Set receive timestamp.\n"
"  --icmp-trans-time <timestamp>    : Set transmit timestamp.\n"
"  --csum <sum>                    : Set a fixed checksum.\n"
"  --badsum                         : Use a random invalid checksum. \n"
"ARP/RARP PROBE MODE:\n"
"  --arp-type <type>                : Type: ARP, ARP-reply, RARP, RARP-reply.\n"
"  --arp-sender-mac <mac>           : Set sender MAC address.\n"
"  --arp-sender-ip  <addr>          : Set sender IP address.\n"
"  --arp-target-mac <mac>           : Set target MAC address.\n"
"  --arp-target-ip  <addr>          : Set target IP address.\n"
"IPv4 OPTIONS:\n"
"  -S, --source-ip                  : Set source IP address.\n"
"  --dest-ip <addr>                 : Set destination IP address (used as an \n"
"                                     alternative to {target specification} ). \n"
"  --tos <tos>                      : Set type of service field (8 bits).\n"
"  --id  <id>                       : Set identification field (16 bits).\n"
"  --df                             : Set Don't Fragment flag.\n"
"  --mf                             : Set More Fragments flag.\n"
"  --rf                             : Set the reserved flag.\n"
"  --ttl <hops>                     : Set time to live [0-255].\n"
"  --fragoff <offset>               : Set the fragment offset (13 bits)"
"  --csum-ip                        : Use a fixed checksum. \n"
"  --badsum-ip                      : Use a random invalid checksum. \n"
"  --ip-options <S|R [route]|L [route]|T|U ...> : Set IP options\n"
"  --ip-options <hex string>                    : Set IP options\n"
"  --mtu <size>                     : Set MTU. Packets get fragmented if MTU is\n"
"                                     small enough.\n"
"IPv6 OPTIONS:\n"
"  -6, --IPv6                       : Use IP version 6.\n"
"  --dest-ip                        : Set destination IP address (used as an\n"
"                                     alternative to {target specification}).\n"
"  --hop-limit                      : Set hop limit (same as IPv4 TTL).\n"
"  --traffic-class <class> :        : Set traffic class.\n"
"  --flow <label>                   : Set flow label.\n"
"ETHERNET OPTIONS:\n"
"  --dest-mac <mac>                 : Set destination mac address. (Disables\n"
"                                     ARP resolution)\n"
"  --source-mac <mac>               : Set source MAC address.\n"
"  --ether-type <type>              : Set EtherType value.\n"
"PAYLOAD OPTIONS:\n"
"  --data <hex string>              : Include a custom payload.\n"
"  --data-string <text>             : Include a custom ASCII text.\n"
"  --data-length <len>              : Include len random bytes as payload.\n"
"ECHO CLIENT/SERVER:\n"
"  --echo-client <passphrase>       : Run Nping in client mode.\n"
"  --echo-server <passphrase>       : Run Nping in server mode.\n"
"  --echo-port <port>               : Use custom <port> to listen or connect.\n"
"  --no-crypto                      : Disable encryption and authentication.\n"
"  --once                           : Stop the server after one connection.\n"
"  --safe-payloads                  : Erase application data in echoed packets.\n"
"TIMING AND PERFORMANCE:\n"
 "  Options which take <time> are in seconds, or append 'ms' (milliseconds),\n"
"  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m, 0.25h).\n"
"  --delay <time>                   : Adjust delay between probes.\n"
"  --rate  <rate>                   : Send num packets per second.\n"
"MISC:\n"
"  -h, --help                       : Display help information.\n"
"  -V, --version                    : Display current version number. \n"
"  -c, --count <n>                  : Stop after <n> rounds.\n"
"  -e, --interface <name>           : Use supplied network interface.\n"
"  -H, --hide-sent                  : Do not display sent packets.\n"
"  -N, --no-capture                 : Do not try to capture replies.\n"
"  --privileged                     : Assume user is fully privileged.\n"
"  --unprivileged                   : Assume user lacks raw socket privileges.\n"
"  --send-eth                       : Send packets at the raw Ethernet layer.\n"
"  --send-ip                        : Send packets using raw IP sockets.\n"
"  --bpf-filter <filter spec>       : Specify custom BPF filter.\n"
"OUTPUT:\n"
"  -v                               : Increment verbosity level by one.\n"
"  -v[level]                        : Set verbosity level. E.g: -v4\n"
"  -d                               : Increment debugging level by one.\n"
"  -d[level]                        : Set debugging level. E.g: -d3\n"
"  -q                               : Decrease verbosity level by one.\n"
"  -q[N]                            : Decrease verbosity level N times\n"
"  --quiet                          : Set verbosity and debug level to minimum.\n"
"  --debug                          : Set verbosity and debug to the max level.\n"
"EXAMPLES:\n"
"  nping scanme.nmap.org\n"
"  nping --tcp -p 80 --flags rst --ttl 2 192.168.1.1\n"
"  nping --icmp --icmp-type time --delay 500ms 192.168.254.254\n"
"  nping --echo-server \"public\" -e wlan0 -vvv \n"
"  nping --echo-client \"public\" echo.nmap.org --tcp -p1-1024 --flags ack\n"
"\n"
"SEE THE MAN PAGE FOR MANY MORE OPTIONS, DESCRIPTIONS, AND EXAMPLES\n\n",
NPING_NAME, NPING_VERSION, NPING_URL);

} /* End of printUsage() */


int ArgParser::parseAdvertEntry(char *str, struct in_addr *addr, u32 *pref){
  char *aux=NULL;
  IPAddress auxIP;
  size_t len=0;
  static char first[256];
  static char last[256];
  memset(first, 0, 256);
  memset(last, 0, 256);

  if (str==NULL || addr==NULL || pref==NULL)
    return OP_FAILURE;

  len =strlen(str);

  /* I guess one can try to lookup something as short as a single char */
  if ( len < strlen("a,1") )
    nping_fatal(QT_3, "Invalid Router Advertising Entry specification: too short");
  /* Im going to limit this to 255 chars. */
  if( len > 255 )
    nping_fatal(QT_3, "Invalid Router Advertising Entry specification: too long");

  /* Let's find the comma */
  aux=strstr(str, ",");

  if(aux==NULL )
    nping_fatal(QT_3, "Invalid Router Advertising Entry specification: Bad syntax, missing comma delimiter");
  if(aux==str)
    nping_fatal(QT_3, "Invalid Router Advertising Entry specification: Bad syntax, comma cannot be placed at start");
  if(aux>=str+len-1 )
    nping_fatal(QT_3, "Invalid Router Advertising Entry specification: Bad syntax, comma cannot be placed at the end");

  /* Looks like at least the syntax is correct */
  memcpy(first, str, aux-str);
  memcpy(last, aux+1, len-(aux-str) );

  if(auxIP.setIPv4Address(first)!=OP_SUCCESS)
    nping_fatal(QT_3, "Invalid Router Advertising Entry specification: Unable to resolve %s", first);
  if(isNumber_u32(last)==false)
    nping_fatal(QT_3, "Invalid Router Advertising Entry specification: %s is not a valid preference number", last);

  *pref=strtoul( last, NULL, 10);
  *addr=auxIP.getIPv4Address();
  return OP_SUCCESS;
} /* End of parseAdvertEntry() */




/* ALLOWED format:
 *
 *  Full option name:              destination-unreachable
 *  Four letters - three letters:  dest-unr
 *  Initials:                      du
 *
 *  In ICMP types that REQUEST something, the word "request" is always omitted.
 *  For example: Echo request should be specified as "echo" or "e",
 *  not "echo-request"/"echo-req"/"er"
 *
 *  EXCEPTIONS. To avoid confusion:
 *      - Initials for "Timestamp" are "tm"
 *      - Initial for Traceroute are "tc"
 * */
int ArgParser::atoICMPType(char *opt, u8 *type){
  if(type==NULL)
    return OP_FAILURE;

  if ( !strcasecmp(opt, "echo-reply") ||
       !strcasecmp(opt, "echo-rep") ||
       !strcasecmp(opt, "er") )
    *type=0;
  else if ( !strcasecmp(opt, "destination-unreachable") ||
            !strcasecmp(opt, "dest-unr") ||
            !strcasecmp(opt, "du") )
    *type=3;
  else if ( !strcasecmp(opt, "source-quench") ||
            !strcasecmp(opt, "sour-que") ||
            !strcasecmp(opt, "sq") )
    *type=4;
  else if ( !strcasecmp(opt, "redirect") ||
            !strcasecmp(opt, "redi") ||
            !strcasecmp(opt, "r") )
    *type=5;
  else if ( !strcasecmp(opt, "echo-request") || /* Ok, I'll also allow this */
            !strcasecmp(opt, "echo") ||
            !strcasecmp(opt, "e") )
    *type=8;
  else if ( !strcasecmp(opt, "router-advertisement") ||
            !strcasecmp(opt, "rout-adv") ||
            !strcasecmp(opt, "ra") )
    *type=9;
  else if ( !strcasecmp(opt, "router-solicitation") ||
            !strcasecmp(opt, "rout-sol") ||
            !strcasecmp(opt, "rs") )
    *type=10;
  else if ( !strcasecmp(opt, "time-exceeded") ||
            !strcasecmp(opt, "time-exc") ||
            !strcasecmp(opt, "te") )
    *type=11;
  else if ( !strcasecmp(opt, "parameter-problem") ||
            !strcasecmp(opt, "para-pro") ||
            !strcasecmp(opt, "pp") )
    *type=12;
  else if ( !strcasecmp(opt, "timestamp") ||
            !strcasecmp(opt, "time") ||
            !strcasecmp(opt, "tm") )
    *type=13;
  else if ( !strcasecmp(opt, "timestamp-reply") ||
            !strcasecmp(opt, "time-rep") ||
            !strcasecmp(opt, "tr") )
    *type=14;
  else if ( !strcasecmp(opt, "information") ||
            !strcasecmp(opt, "info") ||
            !strcasecmp(opt, "i") )
    *type=15;
  else if ( !strcasecmp(opt, "information-reply") ||
            !strcasecmp(opt, "info-rep") ||
            !strcasecmp(opt, "ir") )
    *type=16;
  else if ( !strcasecmp(opt, "mask-request") ||
            !strcasecmp(opt, "mask") ||
            !strcasecmp(opt, "m") )
    *type=17;
  else if ( !strcasecmp(opt, "mask-reply") ||
            !strcasecmp(opt, "mask-rep") ||
            !strcasecmp(opt, "mr") )
    *type=18;
  else if ( !strcasecmp(opt, "traceroute") ||
            !strcasecmp(opt, "trace") ||
            !strcasecmp(opt, "tc") )
    *type=30;
  else
    return OP_FAILURE;

/* TODO: They are not implemented but there are more types in
   http://www.iana.org/assignments/icmp-parameters

 31     Datagram Conversion Error               [RFC1475]
 32     Mobile Host Redirect                    [David Johnson]
 33     IPv6 Where-Are-You                      [Bill Simpson]
 34     IPv6 I-Am-Here                          [Bill Simpson]
 35     Mobile Registration Request             [Bill Simpson]
 36     Mobile Registration Reply               [Bill Simpson]
 37     Domain Name Request                     [RFC1788]
 38     Domain Name Reply                       [RFC1788]
 39     SKIP                                    [Markson]
 40     Photuris                                [RFC2521]
 41     ICMP messages utilized by experimental  [RFC4065]
        mobility protocols such as Seamoby
 42-255 Reserved				                 [JBP]

*/
 return OP_SUCCESS;
} /* End of atoICMPType() */


/* Names are taken from http://www.iana.org/assignments/icmp-parameters */
/* ALLOWED format:
 *
 *  Full option name:              needs-fragmentation
 *  Four letters - three letters:  need-fra
 *  Our own version (varies):      frag
 *
 *  In ICMP types that REQUEST something, the word "request" is always omitted.
 *  For example: Echo request should be specified as "echo" or "e",
 *  not "echo-request"/"echo-req"/"er"
 *
 *  EXCEPTIONS. To avoid confusion:
 *      - Initials for "Timestamp" are "tm"
 *      - Initial for Traceroute are "tc"
 * */
int ArgParser::atoICMPCode(char *opt, u8 *code){

  if(code==NULL || opt==NULL)
    return OP_FAILURE;

  /* Destination Unreachable */
  if ( !strcasecmp(opt, "network-unreachable") ||
       !strcasecmp(opt, "netw-unr") ||
       !strcasecmp(opt, "net") ) /**/
    *code=0;
  else if ( !strcasecmp(opt, "host-unreachable") ||
            !strcasecmp(opt, "host-unr") ||
             !strcasecmp(opt, "host") )
    *code=1;
  else if ( !strcasecmp(opt, "protocol-unreachable") ||
            !strcasecmp(opt, "prot-unr") ||
            !strcasecmp(opt, "proto") )
    *code=2;
  else if ( !strcasecmp(opt, "port-unreachable") ||
            !strcasecmp(opt, "port-unr") ||
            !strcasecmp(opt, "port") )
    *code=3;
  else if ( !strcasecmp(opt, "needs-fragmentation") ||
            !strcasecmp(opt, "need-fra") ||
            !strcasecmp(opt, "frag") )
    *code=4;
  else if ( !strcasecmp(opt, "source-route-failed") ||
            !strcasecmp(opt, "sour-rou") ||
            !strcasecmp(opt, "routefail") )
    *code=5;
  else if ( !strcasecmp(opt, "network-unknown") ||
            !strcasecmp(opt, "netw-unk") ||
            !strcasecmp(opt, "net?") )
    *code=6;
  else if ( !strcasecmp(opt, "host-unknown") ||
            !strcasecmp(opt, "host-unk") ||
            !strcasecmp(opt, "host?") )
    *code=7;
  else if ( !strcasecmp(opt, "host-isolated") ||
            !strcasecmp(opt, "host-iso") ||
            !strcasecmp(opt, "isolated") )
    *code=8;
  else if ( !strcasecmp(opt, "network-prohibited") ||
            !strcasecmp(opt, "netw-pro") ||
            !strcasecmp(opt, "!net") )
    *code=9;
  else if ( !strcasecmp(opt, "host-prohibited") ||
            !strcasecmp(opt, "host-pro") ||
            !strcasecmp(opt, "!host") )
    *code=10;
  else if ( !strcasecmp(opt, "network-tos") ||
            !strcasecmp(opt, "unreachable-network-tos") ||
            !strcasecmp(opt, "netw-tos") ||
            !strcasecmp(opt, "tosnet") )
            /* Not to be confused with redirect-network-tos*/
    *code=11;
  else if ( !strcasecmp(opt, "host-tos") ||
            !strcasecmp(opt, "unreachable-host-tos") ||
            !strcasecmp(opt, "toshost") )
            /* Not to be confused with redirect-network-tos*/
    *code=12;
  else if ( !strcasecmp(opt, "communication-prohibited") ||
            !strcasecmp(opt, "comm-pro") ||
            !strcasecmp(opt, "!comm") )
    *code=13;
  else if ( !strcasecmp(opt, "host-precedence-violation") ||
            !strcasecmp(opt, "precedence-violation") ||
            !strcasecmp(opt, "prec-vio") ||
            !strcasecmp(opt, "violation") )
    *code=14;
  else if ( !strcasecmp(opt, "precedence-cutoff") ||
            !strcasecmp(opt, "prec-cut") ||
            !strcasecmp(opt, "cutoff") )
    *code=15;

  /* Redirect */
  else if ( !strcasecmp(opt, "redirect-network") ||
            !strcasecmp(opt, "redi-net") ||
            !strcasecmp(opt, "net") )
            /* "net" is the same as in Destination unreachable and there is no
             * conflict because both codes use value 0 */
    *code=0;
  else if ( !strcasecmp(opt, "redirect-host") ||
            !strcasecmp(opt, "redi-host") ||
            !strcasecmp(opt, "host") )
            /* "host" is the same as in Destination unreachable and there is no
             * conflict because both codes use value 0 */
    *code=1;
  else if ( !strcasecmp(opt, "redirect-network-tos") ||
            !strcasecmp(opt, "redi-ntos") ||
            !strcasecmp(opt, "redir-ntos") )
    *code=2;
  else if ( !strcasecmp(opt, "redirect-host-tos") ||
            !strcasecmp(opt, "redi-htos") ||
            !strcasecmp(opt, "redir-htos") )
    *code=3;

  /* Router Advertisement */
  else if ( !strcasecmp(opt, "normal-advertisement") ||
            !strcasecmp(opt, "norm-adv") ||
            !strcasecmp(opt, "normal") ||
            !strcasecmp(opt, "zero") ||
            !strcasecmp(opt, "default") ||
            !strcasecmp(opt, "def") )
            /* This one corresponds with "Normal router advertisement" but
             * with the word "normal", can be reused for any other code as
             * 0 is the default value if the code field is unused. */
    *code=0;
  else if ( !strcasecmp(opt, "not-route-common-traffic") ||
            !strcasecmp(opt, "not-rou") ||
            !strcasecmp(opt, "mobile-ip") ||
            !strcasecmp(opt, "!route") ||
            !strcasecmp(opt, "!commontraffic") )
    *code=16;

  /* Time Exceeded */
  else if ( !strcasecmp(opt, "ttl-exceeded-in-transit") ||
            !strcasecmp(opt, "ttl-exc") ||
            !strcasecmp(opt, "ttl-zero") ||
            !strcasecmp(opt, "ttl-transit") ||
            !strcasecmp(opt, "ttl-0") ||
            !strcasecmp(opt, "!ttl") )
    *code=0;
  else if ( !strcasecmp(opt, "fragment-reassembly-time-exceeded") ||
            !strcasecmp(opt, "frag-exc") ||
            !strcasecmp(opt, "frag-time") ||
            !strcasecmp(opt, "!timefrag") ||
            !strcasecmp(opt, "!frag") )
    *code=1;

  /* Parameter problem */
  else if ( !strcasecmp(opt, "pointer-indicates-error") ||
            !strcasecmp(opt, "poin-ind") ||
            !strcasecmp(opt, "pointer-indicates") ||
            !strcasecmp(opt, "pointer") ||
            !strcasecmp(opt, "pointertells") )
    *code=0;
  else if ( !strcasecmp(opt, "missing-required-option") ||
            !strcasecmp(opt, "miss-req") ||
            !strcasecmp(opt, "miss-option") ||
            !strcasecmp(opt, "option-missing") ||
            !strcasecmp(opt, "missing-option") ||
            !strcasecmp(opt, "!option") )
    *code=1;
  else if ( !strcasecmp(opt, "bad-length") ||
            !strcasecmp(opt, "bad-len") ||
            !strcasecmp(opt, "badlen") ||
            !strcasecmp(opt, "badlength") ||
            !strcasecmp(opt, "!len") )
    *code=2;

  /* ICMP Security Failures Messages (Experimental) */
  else if ( !strcasecmp(opt, "bad-spi") ||
            !strcasecmp(opt, "badspi") ||
            !strcasecmp(opt, "!spi") )
    *code=0;
  else if ( !strcasecmp(opt, "authentication-failed") ||
            !strcasecmp(opt, "auth-fai") ||
            !strcasecmp(opt, "auth-failed") ||
            !strcasecmp(opt, "authfail") ||
            !strcasecmp(opt, "!auth") )
    *code=1;
  else if ( !strcasecmp(opt, "decompression-failed") ||
            !strcasecmp(opt, "deco-fai") ||
            !strcasecmp(opt, "decom-failed") ||
            !strcasecmp(opt, "!decompress") ||
            !strcasecmp(opt, "!decompression") )
    *code=2;
  else if ( !strcasecmp(opt, "decryption-failed") ||
            !strcasecmp(opt, "decr-fai") ||
            !strcasecmp(opt, "decrypt-failed") ||
            !strcasecmp(opt, "!decrypt") ||
            !strcasecmp(opt, "!decryption") )
    *code=3;
  else if ( !strcasecmp(opt, "need-authentication") ||
            !strcasecmp(opt, "need-aut") ||
            !strcasecmp(opt, "need-auth") ||
            !strcasecmp(opt, "auth-needed") ||
            !strcasecmp(opt, "!auth") ||
            !strcasecmp(opt, "") )
    *code=4;
  else if ( !strcasecmp(opt, "need-authorization") ||
            !strcasecmp(opt, "need-author") ||
            !strcasecmp(opt, "authorization-needed") ||
            !strcasecmp(opt, "author-needed") ||
            !strcasecmp(opt, "!author") ||
            !strcasecmp(opt, "!authorization") )
    *code=5;
/*
  else if ( !strcasecmp(opt, "") ||
            !strcasecmp(opt, "") ||
            !strcasecmp(opt, "") )
    *code=;
*/
  else
    return OP_FAILURE;

 return OP_SUCCESS;
} /* End of atoICMPCode() */



/* Same as atoICMPCode() but for ARP operation codes */
int ArgParser::atoARPOpCode(char *opt, u16 *code){

  if(code==NULL || opt==NULL)
    return OP_FAILURE;

  if ( !strcasecmp(opt, "arp-request") ||
       !strcasecmp(opt, "arp") ||
       !strcasecmp(opt, "a") ) /**/
    *code=1;
  else if ( !strcasecmp(opt, "arp-reply") ||
            !strcasecmp(opt, "arp-rep") ||
             !strcasecmp(opt, "ar") )
    *code=2;
  else if ( !strcasecmp(opt, "rarp-request") ||
            !strcasecmp(opt, "rarp") ||
            !strcasecmp(opt, "r") )
    *code=3;
  else if ( !strcasecmp(opt, "rarp-reply") ||
            !strcasecmp(opt, "rarp-rep") ||
            !strcasecmp(opt, "rr") )
    *code=4;
  else if ( !strcasecmp(opt, "drarp-request") ||
            !strcasecmp(opt, "drarp") ||
            !strcasecmp(opt, "d") )
    *code=5;
  else if ( !strcasecmp(opt, "drarp-reply") ||
            !strcasecmp(opt, "drarp-rep") ||
            !strcasecmp(opt, "dr") )
    *code=6;
  else if ( !strcasecmp(opt, "drarp-error") ||
            !strcasecmp(opt, "drarp-err") ||
            !strcasecmp(opt, "de") )
    *code=7;
  else if ( !strcasecmp(opt, "inarp-request") ||
       !strcasecmp(opt, "inarp") ||
       !strcasecmp(opt, "i") ) /**/
    *code=8;
  else if ( !strcasecmp(opt, "inarp-reply") ||
       !strcasecmp(opt, "inarp-rep") ||
       !strcasecmp(opt, "ir") ) /**/
    *code=9;
  else if ( !strcasecmp(opt, "arp-nak") ||
            !strcasecmp(opt, "an") )
    *code=10;

/*
  else if ( !strcasecmp(opt, "") ||
            !strcasecmp(opt, "") ||
            !strcasecmp(opt, "") )
    *code=;
*/
  else
    return OP_FAILURE;

 return OP_SUCCESS;
} /* End of atoARPOpCode() */




int ArgParser::atoEtherType(char *opt, u16 *type){
  if(type==NULL || opt==NULL)
    return OP_FAILURE;

  if ( !strcasecmp(opt, "ip") ||
       !strcasecmp(opt, "ipv4") ||
       !strcasecmp(opt, "4") ) /**/
    *type=0x0800;
  else if ( !strcasecmp(opt, "arp") )
    *type=0x0806;
  else if ( !strcasecmp(opt, "frame-relay") ||
            !strcasecmp(opt, "frelay") ||
            !strcasecmp(opt, "fr") )
    *type=0x0808;
  else if ( !strcasecmp(opt, "ppp") )
    *type=0x880B;
  else if ( !strcasecmp(opt, "gsmp") )
    *type=0x880C;
  else if ( !strcasecmp(opt, "rarp") )
    *type=0x8035;
  else if ( !strcasecmp(opt, "ipv6") ||
            !strcasecmp(opt, "6") ) /**/
    *type=0x86DD;
  else if ( !strcasecmp(opt, "mpls") )
    *type=0x8847;
  else if ( !strcasecmp(opt, "mps-ual") ||
            !strcasecmp(opt, "mps") )
    *type=0x8848;
  else if ( !strcasecmp(opt, "mcap") )
    *type=0x8861;
  else if ( !strcasecmp(opt, "pppoe-discovery")||
            !strcasecmp(opt, "pppoe-d") )
    *type=0x8863;
  else if ( !strcasecmp(opt, "pppoe-session")||
            !strcasecmp(opt, "pppoe-s") )
    *type=0x8864;
  else if ( !strcasecmp(opt, "ctag") )
    *type=0x8100;
  else if ( !strcasecmp(opt, "epon") )
    *type=0x8808;
  else if ( !strcasecmp(opt, "pbnac") )
    *type=0x888E;
  else if ( !strcasecmp(opt, "stag") )
    *type=0x88A8;
  else if ( !strcasecmp(opt, "ethexp1") )
    *type=0x88B5;
  else if ( !strcasecmp(opt, "ethexp2") )
    *type=0x88B6;
  else if ( !strcasecmp(opt, "ethoui") )
    *type=0x88B7;
  else if ( !strcasecmp(opt, "preauth") )
    *type=0x88C7;
  else if ( !strcasecmp(opt, "lldp") )
    *type=0x88CC;
  else if ( !strcasecmp(opt, "macsec") ||
            !strcasecmp(opt, "mac-sec") ||
            !strcasecmp(opt, "mac-security") )
    *type=0x88E5;
  else if ( !strcasecmp(opt, "mvrp") )
    *type=0x88F5;
  else if ( !strcasecmp(opt, "mmrp") )
    *type=0x88F6;
  else if ( !strcasecmp(opt, "frrr") )
    *type=0x890D;
/*
  else if ( !strcasecmp(opt, "") ||
            !strcasecmp(opt, "") ||
            !strcasecmp(opt, "") )
    *type=;
*/
  else
    return OP_FAILURE;

 return OP_SUCCESS;

} /* End of atoEtherType() */




int ArgParser::parseICMPTimestamp(char *optarg, u32 *dst){

long diff=0;

  if(optarg==NULL || dst==NULL)
    nping_fatal(QT_3, "parseICMPTimestamp(): NULL pointer supplied.");

  if( meansRandom(optarg) ){
    while( (*dst=get_random_u32()) == 0);
  }
  else if( !strncmp("now-", optarg, 4) ){
    if ( (diff= tval2msecs(optarg+4)) < 0 )
        nping_fatal(QT_3,"You must specify a valid time value after now- (e.g. 1000, 2s, 25m, etc.)");
    struct timeval now;
    gettimeofday(&now, NULL);
    if( ((((u32)now.tv_sec)%86400)*1000) < (u32)diff )
        nping_fatal(QT_3,"Value is %s is too high for current time.", optarg+4 );
    else
        *dst= ((((u32)now.tv_sec)%86400)*1000) - diff;
  }
  else if( !strncmp("now+", optarg, 4) ) {
    if ( (diff= tval2msecs(optarg+4)) < 0 )
        nping_fatal(QT_3,"You must specify a valid time value after now+ (e.g. 1000, 2s, 25m, etc.)");
    struct timeval now;
    gettimeofday(&now, NULL);
    if( ((((u32)now.tv_sec)%86400)*1000) + diff > 0xFFFFFFFF )
        nping_fatal(QT_3,"Value is %s is too high for current time.", optarg+4 );
    else
        *dst= ((((u32)now.tv_sec)%86400)*1000) + diff;
  }
  else if( !strcmp("now", optarg) ) {
    struct timeval now;
    gettimeofday(&now, NULL);
    *dst = ((((u32)now.tv_sec)%86400)*1000);
  }
  else {
    if ( (diff= tval2msecs(optarg)) == -1)
        nping_fatal(QT_3,"Invalid time supplied");
    else
        *dst=diff;
  }

  return OP_SUCCESS;
} /* End of parseICMPTimestamp() */
