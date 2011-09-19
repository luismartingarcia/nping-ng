
/***************************************************************************
 * FPEngine.h -- Header info for IPv6 OS detection via TCP/IP              *
 * fingerprinting.  For more information on how this works in Nmap, see    *
 * http://insecure.org/osdetect/                                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
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
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
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

#ifndef __FPENGINE_H__
#define __FPENGINE_H__ 1

#include "nsock.h"
#include <list>
#include <vector>
#include "nmap.h"
#include "libnetutil/npacket.h"
using namespace std;

/* Mention some classes here so we don't have to place the declarations in
 * the right order (otherwise the compiler complains). */
class FPHost;
class FPHost6;
class FPProbe;

class Target;
class FingerPrintResultsIPv6;

/******************************************************************************
 * CONSTANT DEFINITIONS                                                       *
 ******************************************************************************/

#define NELEMS(a) (sizeof(a) / sizeof((a)[0]))

#define NUM_FP_PROBES_IPv6_TCP    13
#define NUM_FP_PROBES_IPv6_ICMPv6 4
#define NUM_FP_PROBES_IPv6_UDP    1
/* Total number of IPv6 OS detection probes. */
#define NUM_FP_PROBES_IPv6 (NUM_FP_PROBES_IPv6_TCP+NUM_FP_PROBES_IPv6_ICMPv6+NUM_FP_PROBES_IPv6_UDP)

const unsigned int OSDETECT_FLOW_LABEL = 0x12345;



/* Number of timed probes for IPv6 OS scan. This is, the number of probes that
 * have specific timing requirements and need to be processed together. This
 * are the probes that are sent 100ms apart. */
#define NUM_FP_TIMEDPROBES_IPv6 6

/* Initial congestion window. It is set to the number of timed probes because
 * hosts need to be able to schedule all of them at once. */
#define OSSCAN_INITIAL_CWND (NUM_FP_TIMEDPROBES_IPv6)

/* Initial Slow Start threshold. It is set to four times the initial CWND. */
#define OSSCAN_INITIAL_SSTHRESH (4 * OSSCAN_INITIAL_CWND)

/* Host group size is the number of osscan hosts that are processed in parallel.
 * Note that this osscan engine always keeps a working group of this many hosts.
 * in other words, if one host in the group finishes, another is added to it
 * dynamically. */
#define OSSCAN_GROUP_SIZE 10

/* Initial retransmission timeout. This is the time we initially wait for a
 * probe response before retransmitting the original probe. Note that this is
 * only the initial RTO, used only when no RTT measures have been taken yet.
 * The actual RTO varies each time we get a response to a probe.
 * It is set to 3 seconds (3*10^6 usecs) as per RFC 2988. */
#define OSSCAN_INITIAL_RTO (3*1000000)


/******************************************************************************
 * CLASS DEFINITIONS                                                          *
 ******************************************************************************/

/* This class handles the access to the network. It handles packet transmission
 * scheduling, packet capture and congestion control. Every FPHost should be
 * linked to the same instance of this class, so the access to the network can
 * be managed globally (for the whole OS detection process). */
class FPNetworkControl {

 private:
  nsock_pool nsp;            /* Nsock pool.                                         */
  nsock_iod pcap_nsi;        /* Nsock Pcap descriptor.                              */
  nsock_event_id pcap_ev_id; /* Last pcap read event that was scheduled.            */
  bool first_pcap_scheduled; /* True if we scheduled the first pcap read event.     */
  bool nsock_init;           /* True if the nsock pool has been initialized.        */
  int rawsd;                 /* Raw socket.                                         */
  vector<FPHost *> callers;  /* List of users of this instance (used for callbacks).*/
  int probes_sent;           /* Number of unique probes sent (not retransmissions). */
  int responses_recv;        /* Number of probe responses received.                 */
  int probes_timedout;       /* Number of probes that timeout after all retransms.  */
  float cc_cwnd;             /* Current congestion window.                          */
  float cc_ssthresh;         /* Current Slow Start threshold.                       */

  int cc_init();
  int cc_update_sent(int pkts);
  int cc_report_drop();
  int cc_update_received();

 public:
  FPNetworkControl();
  ~FPNetworkControl();
  void init(const char *ifname, devtype iftype);
  int register_caller(FPHost *newcaller);
  int unregister_caller(FPHost *oldcaller);
  int setup_sniffer(const char *iface, const char *bfp_filter);
  void handle_events();
  int scheduleProbe(FPProbe *pkt, int in_msecs_time);
  void probe_transmission_handler(nsock_pool nsp, nsock_event nse, void *arg);
  void response_reception_handler(nsock_pool nsp, nsock_event nse, void *arg);
  bool request_slots(size_t num_packets);
  int cc_report_final_timeout();

};

/*        +-----------+
          | FPEngine  |
          +-----------+
          |           |
          +-----+-----+
                |
        +-------+-------+
        |               |
        |               |
  +-----------+  +-----------+
  | FPEngine4 |  | FPEngine6 |
  +-----------+  +-----------+
  |           |  |           |
  +-----------+  +-----------+ */
/* This class is the generic fingerprinting engine. */
class FPEngine {

 protected:
  size_t osgroup_size;

 public:
  FPEngine();
  ~FPEngine();
  void reset();
  virtual int os_scan(vector<Target *> &Targets) = 0;
  const char *bpf_filter(vector<Target *> &Targets);

};


/* This class handles IPv6 OS fingerprinting. Using it is very simple, just
 * instance it and then call os_scan() with the list of IPv6 targets to
 * fingerprint. If everything goes well, the internal state of the supplied
 * target objects will be modified to reflect the results of the fingerprinting
 * process. */
class FPEngine6 : public FPEngine {

 private:
  vector<FPHost6 *> fphosts; /* Information about each target to fingerprint */

 public:
  FPEngine6();
  ~FPEngine6();
  void reset();
  int os_scan(vector<Target *> &Targets);

};


/*        +----------+
          | FPPacket |
          +----------+
          |          |
          +-----+----+
                |
                |
          +-----------+
          |  FPProbe  |
          +-----------+
          |           |
          +-----+-----+ */
/* This class represents a generic packet for the OS fingerprinting process */
class FPPacket {

 protected:
  PacketElement *pkt;      /* Actual packet associated with this FPPacket     */
  bool link_eth;           /* Ethernet layer required?                        */
  struct eth_nfo eth_hdr;  /* Eth info, valid when this->link_eth==true       */
  struct timeval pkt_time; /* Time at which the packet was sent or received   */

  int resetTime();
  void __reset();

 public:
  FPPacket();
  ~FPPacket();
  int setTime(const struct timeval *tv = NULL);
  struct timeval getTime() const;
  int setPacket(PacketElement *pkt);
  int setEthernet(const u8 *src_mac, const u8 *dst_mac, const char *devname);
  const struct eth_nfo *getEthernet() const;
  const PacketElement *getPacket() const;
  size_t getLength() const;
  u8 *getPacketBuffer(size_t *pkt_len) const;
  bool is_set() const;

};

/* This class represents a generic OS fingerprinting probe. In other words, it
 * represents a network packet that Nmap sends to a target in order to
 * obtain information about the target's TCP/IP stack. */
class FPProbe : public FPPacket {

 private:
   char *probe_id;
   int probe_no;
   int retransmissions;
   int times_replied;
   bool failed;
   bool timed;

 public:
  FPHost *host;

  FPProbe();
  ~FPProbe();
  void reset();
  bool isResponse(PacketElement *rcvd);
  int setProbeID(const char *id);
  const char *getProbeID() const;
  int getRetransmissions() const;
  int incrementRetransmissions();
  int getReplies() const;
  int incrementReplies();
  int setTimeSent();
  int resetTimeSent();
  struct timeval getTimeSent() const;
  bool probeFailed() const;
  int setFailed();
  bool isTimed() const;
  int setTimed();

};

/* This class represents a generic received packet. */
struct FPResponse {
  const char *probe_id;
  u8 *buf;
  size_t len;
  struct timeval senttime, rcvdtime;

  FPResponse(const char *probe_id, const u8 *buf, size_t len,
    struct timeval senttime, struct timeval rcvdtime);
  ~FPResponse();
};


/*        +-----------+
          |   FPHost  |
          +-----------+
          |           |
          +-----+-----+
                |
        +-------+-------+
        |               |
        |               |
  +-----------+  +-----------+
  |  FPHost4  |  |  FPHost6  |
  +-----------+  +-----------+
  |           |  |           |
  +-----------+  +-----------+  */
/* This class represents a generic host to be fingerprinted. */
class FPHost {

 protected:
  unsigned int total_probes;      /* Number of different OS scan probes to be sent to targets     */
  unsigned int timed_probes;      /* Number of probes that have specific timing requirements      */
  unsigned int probes_sent;       /* Number of FPProbes sent (not counting retransmissions)       */
  unsigned int probes_answered;   /* Number of FPResponses received                               */
  unsigned int probes_unanswered; /* Number of FPProbes that timedout (after all retransmissions) */
  bool detection_done;            /* True if the OS detection process has been completed.         */
  bool timedprobes_sent;          /* True if the probes that have timing requirements were sent   */
  Target *target_host;            /* Info about the host to fingerprint                           */
  FPNetworkControl *netctl;       /* Link to the network manager (for scheduling and CC)          */
  bool netctl_registered;         /* True if we are already registered in the network controller  */
  u32 tcpSeqBase;                 /* Base for sequence numbers set in outgoing probes             */
  int open_port_tcp;              /* Open TCP port to be used in the OS detection probes          */
  int closed_port_tcp;            /* Closed TCP port for the OS detection probes.                 */
  int closed_port_udp;            /* Closed UDP port.                                             */
  int tcp_port_base;              /* Send TCP probes starting with this port number.              */
  int udp_port_base;              /* Send UDP probes with this port number.                       */
  u16 icmp_seq_counter;           /* ICMPv6 sequence number counter.                              */
  int rto;                        /* Retransmission timeout for the host                          */
  int rttvar;                     /* Round-Trip Time variation (RFC 2988)                         */
  int srtt;                       /* Smoothed Round-Trip Time (RFC 2988)                          */

  void __reset();
  int update_RTO(int measured_rtt_usecs, bool retransmission);
  int choose_osscan_ports();

 private:
  virtual int build_probe_list() = 0;

 public:
  struct timeval begin_time;

  FPHost();
  ~FPHost();
  virtual bool done() = 0;
  virtual int schedule() = 0;
  virtual int callback(const u8 *pkt, size_t pkt_len, const struct timeval *tv) = 0;
  const struct sockaddr_storage *getTargetAddress();

};

/* This class represents IPv6 hosts to be fingerprinted. The class performs
 * OS detection asynchronously. To use it, shedule() must be called at regular
 * intervals until done() returns true. After that, status() will indicate
 * whether the host was successfully matched with a particular OS or not. */
class FPHost6 : public FPHost {

 private:
  FPProbe fp_probes[NUM_FP_PROBES_IPv6];         /* OS detection probes to be sent.*/
  FPResponse *fp_responses[NUM_FP_PROBES_IPv6];  /* Received responses.            */
  FPResponse *aux_resp[NUM_FP_TIMEDPROBES_IPv6]; /* Aux vector for timed responses */

  int build_probe_list();
  int set_done_and_wrap_up();

 public:
  FPHost6(Target *tgt, FPNetworkControl *fpnc);
  ~FPHost6();
  void reset();
  void init(Target *tgt, FPNetworkControl *fpnc);
  void finish();
  bool done();
  int schedule();
  int callback(const u8 *pkt, size_t pkt_len, const struct timeval *tv);
  const FPProbe *getProbe(const char *id);
  const FPResponse *getResponse(const char *id);

  void fill_FPR(FingerPrintResultsIPv6 *FPR);

};


/******************************************************************************
 * Nsock handler wrappers.                                                    *
 ******************************************************************************/

void probe_transmission_handler_wrapper(nsock_pool nsp, nsock_event nse, void *arg);
void response_reception_handler_wrapper(nsock_pool nsp, nsock_event nse, void *arg);


std::vector<FingerMatch> load_fp_matches();


#endif /* __FPENGINE_H__ */
