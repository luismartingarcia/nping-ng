
/***************************************************************************
 * NpingOps.h -- The NpingOps class contains global options, mostly based  *
 * on user-provided command-line settings.                                 *
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

/* Probe Modes */
#define NO_MODE_SET      0x0000   /* No mode was selected                 */
#define DO_TCP_CONNECT   0x0001   /* Unprivileged TCP connections         */
#define DO_UDP_UNPRIV    0x0002   /* Unprivileged UDP datagrams           */
#define DO_TCP           0x0004   /* Raw TCP                              */
#define DO_UDP           0x0008   /* Raw UDP                              */
#define DO_ICMP          0x0010   /* Raw ICMP for IPv4/IPv6               */
#define DO_ARP           0x0040   /* Raw ARP                              */
#define DO_TRACEROUTE    0x0080   /* Do incremental TTLs (traceroute)     */
#define DO_EXT_HOPOPT    0x0100   /* Add Hop-By-Hop IPv6 extension header */
#define DO_EXT_ROUTING   0x0200   /* Add Routing IPv6 extension header    */
#define DO_EXT_DOPT      0x0400   /* Add destination options IPv6 ext hdr */
#define DO_EXT_FRAGMENT  0x0800   /* Add Fragmentation IPv6 extension hdr */

/* Roles */
#define ROLE_NORMAL 0x22
#define ROLE_CLIENT 0x44
#define ROLE_SERVER 0x66

/* Payload types */
#define PL_NONE 0x00
#define PL_HEX  0xAA
#define PL_RAND 0xBB
#define PL_FILE 0xCC
#define PL_STRING 0xDD

/* Misc */
#define ARP_TYPE_REQUEST  0x01
#define ARP_TYPE_REPLY    0x02
#define RARP_TYPE_REQUEST 0x03
#define RARP_TYPE_REPLY   0x04

#define FLAG_CWR  0  /* Do not change these values because they */
#define FLAG_ECN  1  /* are used as indexes of an array         */
#define FLAG_URG  2
#define FLAG_ACK  3
#define FLAG_PSH  4
#define FLAG_RST  5
#define FLAG_SYN  6
#define FLAG_FIN  7

#define PACKET_SEND_NOPREF 1 /* These have been taken from NmapOps.h */
#define PACKET_SEND_ETH_WEAK 2
#define PACKET_SEND_ETH_STRONG 4
#define PACKET_SEND_ETH 6
#define PACKET_SEND_IP_WEAK 8
#define PACKET_SEND_IP_STRONG 16
#define PACKET_SEND_IP 24

#define IP_VERSION_4 0x04
#define IP_VERSION_6 0x06

#define NOT_SET -1
#define SET_RANDOM -2

#define MAX_ICMP_ADVERT_ENTRIES 128
#define MAX_TARGET_SPECS 1024
#define MAX_TARGET_SPECS 1024
#define MAX_IPv4_NETMASK_ALLOWED 8
#define MAX_IPv6_NETMASK_ALLOWED 104

#include "nping.h"
#include "global_structures.h"
#include "stats.h"
#include "NpingTargets.h"
#include "TargetHost.h"
#include "NetworkInterface.h"
#include "HeaderTemplates.h"
#include <string>

class NpingOps {

  private:

    /* Probe modes */
    u16 modes;                /* Probe modes (TCP,UDP,ICMP,ARP,RARP...)*/

    /* Output */
    int vb;                   /* Current Verbosity level               */
    bool vb_set;
    int dbg;                  /* Current Debugging level               */
    bool dbg_set;
    bool show_sent_pkts;      /* Print packets sent by Nping?          */
    bool show_sent_pkts_set;

    /* Operation and Performance */
    u32 pcount;               /* No of packets 2be sent to each target */
    bool pcount_set;
    int sendpref;             /* Sending preference: eth or raw ip     */
    bool sendpref_set;
    bool send_eth;            /* True: send at raw ethernet level      */
    bool send_eth_set;
    long host_timeout;        /* Timeout for host replies              */
    bool host_timeout_set;
    long delay;               /* Delay between each probe              */
    bool delay_set;
    char device[MAX_DEV_LEN]; /* Network interface                     */
    bool device_set;
    char *bpf_filter_spec;    /* Custom, user-supplied BPF filter spec */
    bool bpf_filter_spec_set;
    int current_round;        /** Current round. Used in traceroute mode */
    bool have_pcap;           /* True if we have access to libpcap     */
    bool disable_packet_capture; /* If false, no packets are captured  */
    bool disable_packet_capture_set;

    /* Privileges */
    bool isr00t;              /* True if current user has root privs   */
    bool isr00t_set;

    /* Payloads */
    int payload_type;         /* Type of payload (RAND,HEX,FILE)       */
    bool payload_type_set;
    u8 *payload_buff;         /* Pointer 2buff with the actual payload */
    bool payload_buff_set;
    int payload_len;          /* Length of payload                     */
    bool payload_len_set;
    char *payload_file;       /* Name of input filename for payload    */
    bool payload_file_set;
    int payload_file_fd;      /* File descriptor for input payload file*/
    bool payload_file_fd_set;

    /* Roles */
    int role;                 /* Nping's role: normal|cliente|server.  */
    bool role_set;

    /* IP Protocol */
    u8 family;                /* IP version to be used in all packets  */

    /* IPv4 */
    u8 ttl;                   /* IPv4 TTL / IPv6 Hop limit             */
    bool ttl_set;
    u8 tos;                   /* Type of service                       */
    bool tos_set;
    u16 identification;       /* Identification field                  */
    bool identification_set;
    bool mf;                  /* More fragments flag                   */
    bool mf_set;
    bool df;                  /* Don't fragment flag                   */
    bool df_set;
    u32 mtu;                  /* Custom MTU len (for IP fragmentation) */
    bool mtu_set;
    bool badsum_ip;           /* Generate invalid checksums in TCP/UDP */
    bool badsum_ip_set;



    char *ip_options;         /* IP Options                            */
    bool ip_options_set;
    IPAddress *spoof_addr;    /* Spoofed source IP address             */

    /* IPv6 */
    u8 ipv6_tclass;           /* Traffic Class                         */
    bool ipv6_tclass_set;
    u32 ipv6_flowlabel;       /* Flow Label                            */
    bool ipv6_flowlabel_set;

    /* TCP / UDP */

    u16 *target_ports;        /* Will point to an array of ports       */
    int tportcount;           /* Total number of target ports          */
    bool target_ports_set;

    u16 *source_ports;        /* Source port for TCP/UPD packets       */
    int sportcount;           /* Total number of source ports          */
    bool source_ports_set;

    bool badsum;              /* Generate invalid TCP/UDP checksums?   */
    bool badsum_set;

    /* ICMP */
    u8 icmp_type;             /* ICMP Type                             */
    bool icmp_type_set;
    u8 icmp_code;             /* ICMP Code                             */
    bool icmp_code_set;
    bool badsum_icmp;         /* Generate invalid ICMP checksums?      */
    bool badsum_icmp_set;
    struct in_addr icmp_redir_addr; /* ICMP Redirect Address */ /* ##TODO## Turn this into an IPAddress object */
    bool icmp_redir_addr_set;
    u8 icmp_paramprob_pnt;    /* ICMP Parameter Problem pointer        */
    bool icmp_paramprob_pnt_set;
    u16 icmp_routeadv_ltime;  /* ICMP Router Advertisement lifetime    */
    bool icmp_routeadv_ltime_set;
    u16 icmp_id;              /* ICMP message identifier               */
    bool icmp_id_set;
    u16 icmp_seq;             /* ICMP sequence number                  */
    bool icmp_seq_set;
    u32 icmp_orig_time;       /* ICMP originate timestamp              */
    bool icmp_orig_time_set;
    u32 icmp_recv_time;       /* ICMP receive timestamp                */
    bool icmp_recv_time_set;
    u32 icmp_trans_time;      /* ICMP transmit timestamp               */
    bool icmp_trans_time_set;
    /* ICMP Router advertisement entries */
    struct in_addr icmp_advert_entry_addr[MAX_ICMP_ADVERT_ENTRIES];
    u32 icmp_advert_entry_pref[MAX_ICMP_ADVERT_ENTRIES];
    int icmp_advert_entry_count;
    bool icmp_advert_entry_set;

    /* Ethernet */
    u8 src_mac[6];            /* Source MAC address                    */
    bool src_mac_set;
    u8 dst_mac[6];            /* Destination MAC address               */
    bool dst_mac_set;
    u16 eth_type;             /* EtherType field of the Ethernet frame */
    bool eth_type_set;

    /* ARP/RARP */
    u16 arp_opcode;           /* ARP Operation code                    */
    bool arp_opcode_set;
    u8 arp_sha[6];            /* ARP Sender hardware address           */
    bool arp_sha_set;
    u8 arp_tha[6];            /* ARP Target hardware address           */
    bool arp_tha_set;
    struct in_addr arp_spa;   /* ARP Sender protocol address           */
    bool arp_spa_set;
    struct in_addr arp_tpa;   /* ARP Target protocol address           */
    bool arp_tpa_set;

    /* Echo mode */
    u16 echo_port;           /* Echo port to listen or connect to      */
    bool echo_port_set;
    char echo_passphrase[1024]; /* User passphrase                     */
    bool echo_passphrase_set;
    bool do_crypto;          /* Do encrypted & authenticated sessions? */
    bool echo_payload;       /* Echo application-layer payloads?       */
    bool echo_payload_set;   
    bool echo_server_once;   /* Run server for only 1 client and quit? */
    bool echo_server_once_set;
    struct timeval last_sent_pkt_time; /* Time last packet was sent    */
    char *delayed_rcvd_str;    /* Delayed RCVD output string           */
    bool delayed_rcvd_str_set; /* Do we have a delayed RCVD string?    */
    nsock_event_id delayed_rcvd_event; /* Nsock event for delayed RCVD */

   private:
    vector<IPAddress *> target_addresses;  /* List of target IP addresses */
    vector<const char *> target_specs;     /* List of user target specs   */

  public:
    vector<TargetHost *> target_hosts;     /* List of Nping target hosts  */
    vector<NetworkInterface *> interfaces; /* List of relevant net ifaces */
    NpingStats stats;                      /* Global statistics           */
    TCPHeaderTemplate tcp;                 /* Header field values for TCP */

  public:

    /* Constructors / Destructors */
    NpingOps();
    ~NpingOps();

    /* Probe modes */
    int addMode(u16 md);
    int delMode(u16 md);
    u16 getModes();
    const char *mode2Ascii(u16 md);
    bool mode(u16 test_value);
    bool issetMode();

    /* Output */
    int setVerbosity(int level);
    int getVerbosity();
    int increaseVerbosity();
    int decreaseVerbosity();
    bool issetVerbosity();

    int setDebugging(int level);
    int getDebugging();
    int increaseDebugging();
    bool issetDebugging();

    int setShowSentPackets(bool val);
    bool showSentPackets();
    bool issetShowSentPackets();

    /* Operation and Performance */
    int setHostTimeout(long t);
    long getHostTimeout();
    bool issetHostTimeout();

    int setDelay(long t);
    long getDelay();
    bool issetDelay();

    int setPacketCount(u32 val);
    u32 getPacketCount();
    bool issetPacketCount();

    int setSendPreference(int v);
    int getSendPreference();
    bool issetSendPreference();
    bool sendPreferenceEthernet();
    bool sendPreferenceIP();

    int setSendEth(bool val);
    bool sendEth();
    bool issetSendEth();

    int setDevice(char *n);
    char *getDevice();
    bool issetDevice();

    int setBPFFilterSpec(char *val);
    char *getBPFFilterSpec();
    bool issetBPFFilterSpec();

    int setCurrentRound(int val);
    int getCurrentRound();
    bool issetCurrentRound();

    bool havePcap();
    int setHavePcap(bool val);

    int setDisablePacketCapture(bool val);
    bool disablePacketCapture();
    bool issetDisablePacketCapture();

    int setAddressFamily(int addrfamily);
    bool ipv4();
    bool ipv6();
    int af();

    /* Privileges */
    int setIsRoot(int v);
    int setIsRoot();
    bool isRoot();
    bool issetIsRoot();

    /* Payloads */
    int setPayloadType(int t);
    int getPayloadType();
    bool issetPayloadType();
    int setPayloadBuffer(u8 *p, int len);
    u8 *getPayloadBuffer();
    bool issetPayloadBuffer();
    int getPayloadLen();
    bool issetPayloadLen();

    /* Roles */
    int setRole(int r);
    int setRoleClient();
    int setRoleServer();
    int setRoleNormal();
    int getRole();
    bool issetRole();

    /* IPv4 */
    bool enableBadsumIP();
    bool disableBadsumIP();
    bool getBadsumIP();
    bool issetBadsumIP();

    int setTTL(u8 t);
    u8 getTTL();
    bool issetTTL();

    int setTOS(u8 tos);
    u8 getTOS();
    bool issetTOS();

    int setIdentification(u16 i);
    u16 getIdentification();
    bool issetIdentification();

    int setMF();
    bool getMF();
    bool issetMF();

    int setDF();
    bool getDF();
    bool issetDF();

    int setIPOptions(char *txt);
    char *getIPOptions();
    bool issetIPOptions();

    int setMTU(u32 t);
    u32 getMTU();
    bool issetMTU();

    IPAddress *getSpoofAddress();
    int setSpoofAddress(IPAddress *addr);
    int setSpoofAddress(IPAddress addr);


    /* IPv6 */
    int setTrafficClass(u8 val);
    u8 getTrafficClass();
    bool issetTrafficClass();

    int setFlowLabel(u32 val);
    u32 getFlowLabel();
    bool issetFlowLabel();

    int setHopLimit(u8 t);
    u8 getHopLimit();
    bool issetHopLimit();

    /* TCP / UDP */
    u16 *getTargetPorts(u16 *len);
    int setTargetPorts(u16 *ports_array, u16 total_ports);
    bool issetTargetPorts();
    bool scan_mode_uses_target_ports(int mode);

    int setSourcePorts(u16 *ports_array, u16 total_ports);
    u16 *getSourcePorts(u16 *len);
    bool issetSourcePorts();

    bool enableBadsum();
    bool disableBadsum();
    bool getBadsum();
    bool issetBadsum();

    /* ICMP */
    int setICMPType(u8 type);
    u8 getICMPType();
    bool issetICMPType();

    int setICMPCode(u8 val);
    u8 getICMPCode();
    bool issetICMPCode();

    bool enableBadsumICMP();
    bool disableBadsumICMP();
    bool getBadsumICMP();
    bool issetBadsumICMP();

    int setICMPRedirectAddress(struct in_addr val);
    struct in_addr getICMPRedirectAddress();
    bool issetICMPRedirectAddress();

    int setICMPParamProblemPointer(u8 val);
    u8 getICMPParamProblemPointer();
    bool issetICMPParamProblemPointer();

    int setICMPRouterAdvLifetime(u16 val);
    u16 getICMPRouterAdvLifetime();
    bool issetICMPRouterAdvLifetime();

    int setICMPIdentifier(u16 val);
    u16 getICMPIdentifier();
    bool issetICMPIdentifier();

    int setICMPSequence(u16 val);
    u16 getICMPSequence();
    bool issetICMPSequence();

    int setICMPOriginateTimestamp(u32 val);
    u32 getICMPOriginateTimestamp();
    bool issetICMPOriginateTimestamp();

    int setICMPReceiveTimestamp(u32 val);
    u32 getICMPReceiveTimestamp();
    bool issetICMPReceiveTimestamp();

    int setICMPTransmitTimestamp(u32 val);
    u32 getICMPTransmitTimestamp();
    bool issetICMPTransmitTimestamp();

    int addICMPAdvertEntry(struct in_addr addr, u32 pref );
    int getICMPAdvertEntry(int num, struct in_addr *addr, u32 *pref);
    int getICMPAdvertEntryCount();
    bool issetICMPAdvertEntry();

    /* Ethernet */
    int setSourceMAC(u8 * val);
    u8 * getSourceMAC();
    bool issetSourceMAC();

    int setDestMAC(u8 * val);
    u8 * getDestMAC();
    bool issetDestMAC();

    int setEtherType(u16 val);
    u16 getEtherType();
    bool issetEtherType();

    /* ARP/RARP */
    int setARPOpCode(u16 val);
    u16 getARPOpCode();
    bool issetARPOpCode();

    int setARPSenderHwAddr(u8 * val);
    u8 * getARPSenderHwAddr();
    bool issetARPSenderHwAddr();

    int setARPTargetHwAddr(u8 * val);
    u8 * getARPTargetHwAddr();
    bool issetARPTargetHwAddr();

    int setARPSenderProtoAddr(struct in_addr val);
    struct in_addr getARPSenderProtoAddr();
    bool issetARPSenderProtoAddr();

    int setARPTargetProtoAddr(struct in_addr val);
    struct in_addr getARPTargetProtoAddr();
    bool issetARPTargetProtoAddr();

    /* Echo Mode */
    int setEchoPort(u16 val);
    u16 getEchoPort();
    bool issetEchoPort();

    int setEchoPassphrase(const char *str);
    char *getEchoPassphrase();
    bool issetEchoPassphrase();

    bool doCrypto();
    int doCrypto(bool value);

    bool echoPayload();
    int echoPayload(bool value);

    int setOnce(bool val);
    bool once();

    /* Validation */
    void validateOptions();
    bool canRunUDPWithoutPrivileges();
    char *select_network_iface();

    /* Misc */
    void displayNpingDoneMsg();
    void displayStatistics();
    int cleanup();
    int setDefaultHeaderValues();

    int setLastPacketSentTime(struct timeval t);
    struct timeval getLastPacketSentTime();

    int setDelayedRcvd(const char *str, nsock_event_id id);
    char *getDelayedRcvd(nsock_event_id *id);

    /* TargetHost handling */
    int addTargetSpec(const char *spec);
    int setupTargetHosts();
    u32 totalTargetHosts();

}; /* End of class NpingOps */

