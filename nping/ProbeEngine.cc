
/***************************************************************************
 * ProbeEngine.cc -- Probe Mode is Nping's default working mode. Basically,*
 * it involves sending the packets that the user requested at regular      *
 * intervals and capturing responses from the wire.                        *
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

#include "nping.h"
#include "ProbeEngine.h"
#include <vector>
#include "nsock.h"
#include "output.h"
#include "NpingOps.h"

extern NpingOps o;
extern ProbeEngine prob;

ProbeEngine::ProbeEngine() {
  this->reset();
} /* End of ProbeEngine constructor */


ProbeEngine::~ProbeEngine() {
} /* End of ProbeEngine destructor */


/** Sets every attribute to its default value- */
void ProbeEngine::reset() {
  this->nsock_init=false;
  memset(&start_time, 0, sizeof(struct timeval));
  this->rawsd4=-1;
  this->rawsd6=-1;
} /* End of reset() */


/** Sets up the internal nsock pool and the nsock trace level */
int ProbeEngine::init_nsock(){
  struct timeval now;
  if( nsock_init==false ){
      /* Create a new nsock pool */
      if ((nsp = nsp_new(NULL)) == NULL)
        nping_fatal(QT_3, "Failed to create new pool.  QUITTING.\n");

      /* Allow broadcast addresses */
      nsp_setbroadcast(nsp, 1);

      /* Set nsock trace level */
      gettimeofday(&now, NULL);
      if( o.getDebugging() == DBG_5)
        nsp_settrace(nsp, NULL, 1 , &now);
      else if( o.getDebugging() > DBG_5 )
        nsp_settrace(nsp, NULL, 10 , &now);
      /* Flag it as already initialized so we don't do it again */
      nsock_init=true;
  }
  return OP_SUCCESS;
} /* End of init() */


/** Cleans up the internal nsock pool and any other internal data that
  * needs to be taken care of before destroying the object. */
int ProbeEngine::cleanup(){
  nsp_delete(this->nsp);
  return OP_SUCCESS;
} /* End of cleanup() */


/** Returns the internal nsock pool.
  * @warning the caller must ensure that init_nsock() has been called before
  * calling this method; otherwise, it will fatal() */
nsock_pool ProbeEngine::getNsockPool(){
  if( this->nsock_init==false)
    nping_fatal(QT_3, "getNsockPool() called before init_nsock(). Please report a bug.");
  return this->nsp;
} /* End of getNsockPool() */



/* This method gets the probe engine ready for packet capture. Basically it
 * obtains a pcap descriptor from nsock and sets an appropriate BPF filter. */
int ProbeEngine::setup_sniffer(vector<NetworkInterface *> &ifacelist, vector<const char *>bpf_filters){
  char *errmsg = NULL;
  char pcapdev[128];
  nsock_iod my_pcap_iod;

  assert(ifacelist.size()==bpf_filters.size());

  for(u32 i=0; i<ifacelist.size(); i++){

    /* Get a new descriptor from Nsock and associate it with the interface name
     * it belongs to. */
    my_pcap_iod=nsi_new(this->nsp, (void *)ifacelist[i]->getName());

    /* Do some magic to make pcap names work in Windows. Nping may use device
     * names obtained through dnet, but WinPcap has its own naming system, so
     * the conversion is done here*/
    #ifdef WIN32
      if (!DnetName2PcapName(ifacelist[i]->getName(), pcapdev, sizeof(pcapdev))) {
        /* Couldn't find the corresponding dev. We'll try with the one we have */
        Strncpy(pcapdev, ifacelist[i]->getName(), sizeof(pcapdev));
      }
    #else
      Strncpy(pcapdev, ifacelist[i]->getName(), sizeof(pcapdev));
    #endif

    /* Obtain the pcap descriptor */
    if ((errmsg = nsock_pcap_open(this->nsp, my_pcap_iod, pcapdev, 8192, o.getSpoofAddress() ? 1 : 0, bpf_filters[i])) != NULL)
      nping_fatal(QT_3, "Error opening capture device %s --> %s", pcapdev, errmsg);

    /* Add the IOD for the current interface to the list of pcap IODs */
    this->pcap_iods.push_back(my_pcap_iod);
  }
  return OP_SUCCESS;
} /* End of setup_sniffer() */


/** This function handles regular ping mode. Basically it handles both
  * unprivileged modes (TCP_CONNECT and UDP_UNPRIV) and raw packet modes
  * (TCP, UDP, ICMP, ARP). This function is where the loops that iterate
  * over target hosts and target ports are located. It uses the nsock lib
  * to schedule transmissions. The actual Tx and Rx is done inside the nsock
  * event handlers, here we just schedule them, take care of the timers,
  * set up pcap and the bpf filter, etc. */
int ProbeEngine::start(vector<TargetHost *> &Targets, vector<NetworkInterface *> &Interfaces){
  const char *filter = NULL;
  vector<const char *>bpf_filters;
  vector<PacketElement *> Packets;
  struct timeval now, now2, next_time;
  int wait_time=0, time_deviation=0;
  u16 total_ports=0;
  u32 count=1;

  nping_print(DBG_1, "Starting Nping Probe Engine...");

  /* Initialize Nsock */
  this->init_nsock();
  o.getTargetPorts(&total_ports);
  total_ports = (total_ports==0) ? 1 : total_ports;

  /* Build a BPF filter for each interface */
  for(u32 i=0; i<Interfaces.size(); i++){
    filter = this->bpf_filter(Targets, Interfaces[i]);
    assert(filter!=NULL);
    bpf_filters.push_back(strdup(filter));
    nping_print(DBG_2, "[ProbeEngine] Interface=%s BPF:%s", Interfaces[i]->getName(), filter);
  }

  /* Set up the sniffer(s) */
  this->setup_sniffer(Interfaces, bpf_filters);

  /* Init the time counters */
  gettimeofday(&this->start_time, NULL);

  /* Schedule the first pcap read event (one for each interface we use) */
  for(size_t i=0; i<this->pcap_iods.size(); i++){
    nsock_pcap_read_packet(this->nsp, this->pcap_iods[i], packet_capture_handler_wrapper, -1, NULL);
  }

  /* Do the Probe Mode rounds! */
  for(unsigned int r=0; r<o.getRounds(); r++){

    for(unsigned int p=0; p<total_ports; p++){

      for(unsigned int t = 0; t < Targets.size(); t++){

        /* Obtain a list of packets to send (each TargetHost adds whatever
         * packets it wants to send to the supplied vector) */
        Targets[t]->getNextPacketBatch(Packets);

        /* Here, schedule the immediate transmission of all the packets
         * provided by the TargetHosts. */
        nping_print(DBG_2, "Starting transmission of %d packets", (int)Packets.size());
        gettimeofday(&now, NULL);
        while(Packets.size()>0){
            this->send_packet(Targets[t], Packets[0], &now);
           /* Delete the packet we've just sent from the list so we don't send
            * it again the next time */
           Packets.erase(Packets.begin(), Packets.begin()+1);
        }

        /* Determine how long do we have to wait until we send the next pkt */
        TIMEVAL_MSEC_ADD(next_time, start_time, count*o.getDelay() );
        if((wait_time=TIMEVAL_MSEC_SUBTRACT(next_time, now)-time_deviation) < 0){
          nping_print(DBG_1, "Wait time < 0 ! (wait_time=%d)", wait_time);
          wait_time=0;
        }

        /* Now schedule a dummy wait event so we don't send more packets
         * until the inter-packet delay has passed */
        nsock_timer_create(nsp, interpacket_delay_wait_handler, wait_time, NULL);

        /* Now wait until all events have been dispatched */
        nsock_loop(this->nsp, -1);

        /* Let's see what time it is now so we can determine if we got the
         * wait_time right. If we didn't, we compute the time deviation and
         * apply it in the next iteration. */
        gettimeofday(&now2, NULL);
        if((time_deviation=TIMEVAL_MSEC_SUBTRACT(now2, now) - wait_time)<0){
          time_deviation=0;
        }
        count++;
      }
    }
  }

  /* Cleanup and return */
  nping_print(DBG_1, "Nping Probe Engine Finished.");
  return OP_SUCCESS;

} /* End of start() */


/* This function creates a BPF filter specification, suitable to be passed to
 * pcap_compile() or nsock_pcap_open(). Note that @param target_interface
 * determines which subset of @param Targets will be considered for the
 * BPF filter. In other words, if we have some targets that use eth0 and a
 * target that uses "lo", then if "target_interface" is "lo", only the right
 * target host will be included in the filter. Same thing for "eth0", etc.
 * If less than 20 targets are associated with the supplied interfacer,
 * the filter contains an explicit list of target addresses. It looks similar
 * to this:
 *
 * dst host fe80::250:56ff:fec0:1 and (src host fe80::20c:29ff:feb0:2316 or src host fe80::20c:29ff:fe9f:5bc2)
 *
 * When more than 20 targets are passed, a generic filter based on the source
 * address is used. The returned filter looks something like:
 *
 * dst host fe80::250:56ff:fec0:1
 *
 * @warning Returned pointer is a statically allocated buffer that subsequent
 *  calls will overwrite. */
char *ProbeEngine::bpf_filter(vector<TargetHost *> &Targets, NetworkInterface *target_interface){
  static char pcap_filter[2048];
  /* 20 IPv6 addresses is max (46 byte addy + 14 (" or src host ")) * 20 == 1200 */
  char dst_hosts[1220];
  int filterlen=0;
  int len=0;
  unsigned int targetno;
  memset(pcap_filter, 0, sizeof(pcap_filter));
  IPAddress *src_addr=NULL;
  bool first=true;

  /* If the user specified a custom BPF filter, use it. */
  if(o.issetBPFFilterSpec())
    return o.getBPFFilterSpec();

  /* If we have 20 or less targets, build a list of addresses so we can set
   * an explicit BPF filter */
  if (target_interface->associatedHosts() <= 20) {
    /* Iterate over all targets so we can build the list of addresses we
     * expect packets from */
    for(targetno = 0; targetno < Targets.size(); targetno++) {
      /* Only process hosts whose network interface matches target_interface */
      if( strcmp(Targets[targetno]->getInterface()->getName(), target_interface->getName()) ){
        continue;
      }else if(first){
        src_addr=Targets[targetno]->getSourceAddress();
      }
      len = Snprintf(dst_hosts + filterlen,
                     sizeof(dst_hosts) - filterlen,
                     "%ssrc host %s", (first)? "" : " or ",
                     Targets[targetno]->getTargetAddress()->toString());
      first=false;
      if (len < 0 || len + filterlen >= (int) sizeof(dst_hosts))
        nping_fatal(QT_3, "ran out of space in dst_hosts");
      filterlen += len;
    }
    /* Now build the actual BPF filter, where we specify the address we expect
     * the packets to be directed to (our address) and the address we expect
     * the packets to come from */
    if (len < 0 || len + filterlen >= (int) sizeof(dst_hosts))
      nping_fatal(QT_3, "ran out of space in dst_hosts");
    len = Snprintf(pcap_filter, sizeof(pcap_filter), "dst host %s and (%s)",
                   src_addr->toString(), dst_hosts);
  /* If we have too many targets to list every single IP address that we
   * plan to send packets too, just set the filter with our own address, so
   * we only capture packets destined to the source address we chose for the
   * packets we sent. */
  }else{
    /* Find the first target that uses our interface so we can extract the source
     * IP address */
    for(targetno = 0; targetno < Targets.size(); targetno++) {
      /* Only process hosts whose network interface matches target_interface */
      if( strcmp(Targets[targetno]->getInterface()->getName(), target_interface->getName()) ){
        continue;
      }else{
        src_addr=Targets[targetno]->getSourceAddress();
        break;
      }
    }
    len = Snprintf(pcap_filter, sizeof(pcap_filter), "dst host %s", src_addr->toString());
  }
  /* Make sure we haven't screwed up */
  if (len < 0 || len >= (int) sizeof(pcap_filter))
    nping_fatal(QT_3, "ran out of space in pcap filter");
  return pcap_filter;
} /* End of bpf_filter() */



int ProbeEngine::send_packet(TargetHost *tgt, PacketElement *pkt, struct timeval *now){
  eth_t *ethsd=NULL;       /* DNET Ethernet handler                 */
  struct sockaddr_in s4;   /* Target IPv4 address                   */
  struct sockaddr_in6 s6;  /* Target IPv6 address                   */
  u8 pktbuff[65535];       /* Binary buffer for the outgoing packet */
  assert(tgt!=NULL && pkt!=NULL);
  pkt->dumpToBinaryBuffer(pktbuff, 65535);

  /* Now decide whether the packet should be transmitted at the raw Ethernet
   * level or at the IP level. TargetHosts are already aware of their needs
   * so if the PacketElement that we got starts with an Ethernet frame,
   * that means we have to inject and Ethernet frame. Otherwise we do raw IP. */
  if(pkt->protocol_id()==HEADER_TYPE_ETHERNET){
    /* Determine which interface we should use for the packet */
    NetworkInterface *dev=tgt->getInterface();
    assert(dev!=NULL);

    /* Obtain an Ethernet handler from DNET */
    if((ethsd=eth_open_cached(dev->getName()))==NULL)
      nping_fatal(QT_3, "%s: Failed to open ethernet device (%s)", __func__, dev->getName());

    /* Inject the packet into the wire */
    if(eth_send(ethsd, pktbuff, pkt->getLen()) < pkt->getLen()){
      nping_warning(QT_2, "Failed to send Ethernet frame through %s", dev->getName());
      return OP_FAILURE;
    }
  }else if(pkt->protocol_id()==HEADER_TYPE_IPv4){
    tgt->getTargetAddress()->getIPv4Address(&s4);
    /* First time this is called, we obtain a raw socket for IPv4 */
    if(this->rawsd4<0){
      if((this->rawsd4=socket(AF_INET, SOCK_RAW, IPPROTO_RAW))<0){
        nping_fatal(QT_3, "%s(): Unable to obtain raw socket.", __func__);
      }
    }
    send_ip_packet_sd(this->rawsd4, &s4, pktbuff, pkt->getLen() );
  }else if(pkt->protocol_id()==HEADER_TYPE_IPv6){
    tgt->getTargetAddress()->getIPv6Address(&s6);
    send_ipv6_packet_eth_or_sd(-1, NULL, &s6, pktbuff, pkt->getLen());
  }else{
    nping_fatal(QT_3, "%s(): Unknown protocol", __func__);
  }

  /* Finally, print the packet we've just sent */
  if(o.showSentPackets()){
    nping_print(VB_0|NO_NEWLINE,"SENT (%.4fs) ", ((double)TIMEVAL_MSEC_SUBTRACT(*now, this->start_time)) / 1000);
    if(o.showEth()==false && pkt->protocol_id()==HEADER_TYPE_ETHERNET){
      pkt->getNextElement()->print(stdout, o.getDetailLevel());
    }else{
      pkt->print(stdout, o.getDetailLevel());
    }
    printf("\n");
  }
  return OP_SUCCESS;
} /* End of send_packet() */


/* This method is the handler for PCAP_READ events. In other words, every time
 * nsock captures a packet from the wire, this method is called. In it, we
 * parse the captured packet and decide if it corresponds to a reply to one of
 * the probes we've already sent. If it does, the contents are printed out and
 * the statistics are updated. */
int ProbeEngine::packet_capture_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nsock_iod nsi = nse_iod(nse);
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  const u8 *rcvd_pkt = NULL;                /* Points to the captured packet */
  size_t rcvd_pkt_len = 0;                  /* Lenght of the captured packet */
  struct timeval pcaptime;                  /* Time the packet was captured  */
  struct timeval now;
  gettimeofday(&now, NULL);
  PacketElement *pkt=NULL;

  if (status == NSE_STATUS_SUCCESS) {
    switch(type) {

      case NSE_TYPE_PCAP_READ:

        /* Schedule a new pcap read operation */
        nsock_pcap_read_packet(nsp, nsi, packet_capture_handler_wrapper, -1, NULL);

        /* Get captured packet */
        nse_readpcap(nse, NULL, NULL, &rcvd_pkt, &rcvd_pkt_len, NULL, &pcaptime);

        /* Here, we convert the raw hex buffer into a nice chain of PacketElement
         * objects. */
        if((pkt=PacketParser::split(rcvd_pkt, rcvd_pkt_len, false))!=NULL){
            /* Now let's lee if the captured packet is a response to a probe
             * we've sent before. What we do is iterate over the list of
             * target hosts and ask each of those hosts to check if that's the
             * case. */
            for(size_t i=0; i<o.target_hosts.size(); i++){
                if(o.target_hosts[i]->is_response(pkt)){
                  nping_print(VB_0|NO_NEWLINE,"RCVD (%.4fs) ", ((double)TIMEVAL_MSEC_SUBTRACT(now, this->start_time)) / 1000);
                  pkt->print(stdout, o.getDetailLevel());
                  printf("\n");
                  // TODO: @todo Here update general stats. (the is_response()
                  // call already updates the host's internal stats.
                }
            }
        }
      break;

      default:
       nping_fatal(QT_3, "Unexpected Nsock event in %s()",__func__);
      break;

    } /* switch(type) */

  } else if (status == NSE_STATUS_EOF) {
    nping_print(DBG_4,"response_reception_handler(): EOF\n");
  } else if (status == NSE_STATUS_ERROR) {
    nping_print(DBG_4, "%s(): %s failed: %s\n", __func__, nse_type2str(type), strerror(socket_errno()));
  } else if (status == NSE_STATUS_TIMEOUT) {
    nping_print(DBG_4, "%s(): %s timeout: %s\n", __func__, nse_type2str(type), strerror(socket_errno()));
  } else if (status == NSE_STATUS_CANCELLED) {
    nping_print(DBG_4, "%s(): %s canceled: %s\n", __func__, nse_type2str(type), strerror(socket_errno()));
  } else if (status == NSE_STATUS_KILL) {
    nping_print(DBG_4, "%s(): %s killed: %s\n", __func__, nse_type2str(type), strerror(socket_errno()));
  } else {
    nping_print(DBG_4, "%s(): Unknown status code %d\n", __func__, status);
  }
  return OP_SUCCESS;
} /* End of packet_capture_handler() */


/******************************************************************************
 * Nsock handlers and handler wrappers.                                       *
 ******************************************************************************/


/* This handler is a dummy handler used to keep the interpacket delay between
 * packet schedule operations. When this handler is called by nsock, it means
 * it's time for another round of packets. We just call nsock_loop_quit() so
 * packet capture events don't make us miss the next round of probe
 * transmissions */
void interpacket_delay_wait_handler(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  nsock_loop_quit(nsp);
  return;
} /* End of interpacket_delay_wait_handler() */



/* This handler is a wrapper for the ProbeEngine::packet_capture_handler()
 * method. We need this because C++ does not allow to use class methods as
 * callback functions for things like signal() or the Nsock lib. */
void packet_capture_handler_wrapper(nsock_pool nsp, nsock_event nse, void *arg){
  nping_print(DBG_4, "%s()", __func__);
  prob.packet_capture_handler(nsp, nse, arg);
  return;
} /* End of packet_capture_handler_wrapper() */
