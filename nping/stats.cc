
/***************************************************************************
 * PacketStats.cc -- The PacketStats class handles packet statistics. It   *
 * is intended to keep track of the number of packets and bytes sent and   *
 * received, keep track of start and finish times, etc.                    *
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
#include "stats.h"
#include "NpingOps.h"
#include "output.h"



/*****************************************************************************/
/* Implementation of NpingTimer class.                                       */
/*****************************************************************************/

NpingTimer::NpingTimer(){
  this->reset();
}


NpingTimer::~NpingTimer(){

}

void NpingTimer::reset(){
  this->start_tv.tv_sec=0;
  this->start_tv.tv_usec=0;
  this->stop_tv.tv_sec=0;
  this->stop_tv.tv_usec=0;
} /* End of reset() */


int NpingTimer::start(){
  if( timeval_set(&start_tv) || timeval_set(&stop_tv) )
    return OP_FAILURE;
  gettimeofday(&start_tv, NULL);
  return OP_SUCCESS;
} /* End of start() */


int NpingTimer::stop(){
  if( !timeval_set(&start_tv) || timeval_set(&stop_tv) )
    return OP_FAILURE;
  gettimeofday(&stop_tv, NULL);
  return OP_SUCCESS;
} /* End of stop() */


double NpingTimer::elapsed(struct timeval *now){
  struct timeval tv;
  const struct timeval *end_tv=NULL;
  /* If for some reason the clock has not been started,
   * just return 0 seconds elapsed. */
  if(!timeval_set(&start_tv)){
    return 0.0;
  }
  /* If the caller supplied a time, use it */
  if(now!=NULL){
    end_tv=now;
  /* If the clock has been stopped already, use the stop time */
  }else if(timeval_set(&stop_tv)){
    end_tv = &stop_tv;
  }else{
    gettimeofday(&tv, NULL);
    end_tv = &tv;
  }
  return TIMEVAL_SUBTRACT(*end_tv, start_tv) / 1000000.0;
} /* End of elapsed() */


bool NpingTimer::is_started(){
  return timeval_set(&this->start_tv);
} /* End of is_started() */


bool NpingTimer::is_stopped(){
  return timeval_set(&this->stop_tv);
} /* End of is_stopped() */


/* Returns true if tv has been initialized; i.e., its members are not all zero. */
bool NpingTimer::timeval_set(const struct timeval *tv){
  return (tv->tv_sec != 0 || tv->tv_usec != 0);
} /* End of timeval_set() */


/*****************************************************************************/
/* Implementation of NpingStats class.                                       */
/*****************************************************************************/

PacketStats::PacketStats(){
  this->reset();
} /* End of PacketStats constructor */


PacketStats::~PacketStats(){

} /* End of PacketStats destructor */


void PacketStats::reset(){
  memset(&this->packets, 0, sizeof(this->packets));
  memset(&this->bytes, 0, sizeof(this->bytes));
  memset(&this->tcp, 0, sizeof(this->tcp));
  memset(&this->udp, 0, sizeof(this->udp));
  memset(&this->icmp4, 0, sizeof(this->icmp4));
  memset(&this->icmp6, 0, sizeof(this->icmp6));
  memset(&this->arp, 0, sizeof(this->arp));
  memset(&this->ip4, 0, sizeof(this->ip4));
  memset(&this->ip6, 0, sizeof(this->ip6));
  this->echo_clients_served=0;
  this->max_rtt=-1;
  this->min_rtt=-1;
  this->avg_rtt=-1;
  this->tx_timer.reset();
  this->rx_timer.reset();
  this->run_timer.reset();
} /* End of reset() */


/* Takes a protocol and returns the appropriate stats array. */
u64 *PacketStats::proto2stats(int proto){
  switch(proto){

      case STATS_TCP:
        return this->tcp;
      break;

      case STATS_UDP:
        return this->udp;
      break;

      case STATS_ICMPv4:
        return this->icmp4;
      break;

      case STATS_ICMPv6:
        return this->icmp6;
      break;

      case STATS_ARP:
        return this->arp;
      break;

      case STATS_IPv4:
        return this->ip4;
      break;

      case STATS_IPv6:
        return this->ip4;
      break;

      case STATS_TOTAL:
        return this->packets;
      break;
  }
  return NULL;
} /* End of proto2stats() */


/** Updates packet and byte count for sent/received/echoed packets. This
  * method is meant to be used internally. Use the update_sent(), update_rcvd()
  * and update_echoed() instead. */
int PacketStats::update_count(int index, int ip_version, int proto, u32 pkt_len){
  assert(index>=INDEX_SENT && index<=INDEX_ACCEPTS);

  /* General packet and byte count */
  this->packets[index]++;
  this->bytes[index]+=pkt_len;

  /* IP stats */
  switch(ip_version){
    case AF_INET:
      this->ip4[index]++;
    break;
    case AF_INET6:
      this->ip6[index]++;
    break;
  }
  /* Stats for protocols above IP */
  switch(proto){
    case HEADER_TYPE_ICMPv4:
      this->icmp4[index]++;
    break;
    case HEADER_TYPE_ICMPv6:
      this->icmp6[index]++;
    break;
    case HEADER_TYPE_TCP:
      this->tcp[index]++;
    break;
    case HEADER_TYPE_UDP:
      this->udp[index]++;
    break;
    case HEADER_TYPE_ARP:
      this->arp[index]++;
    break;
  }

  return OP_SUCCESS;
} /* End of update_count() */


u64 PacketStats::get_stat(int proto, int index){
  u64 *protostats = this->proto2stats(proto);
  assert(protostats!=NULL);
  assert(index>=INDEX_SENT && index<=INDEX_ACCEPTS);
  return protostats[index];
} /* End of get_stat() */


u64 PacketStats::get_difference(int proto, int index_expected, int index_actual){
  if(this->get_stat(proto, index_expected) <= this->get_stat(proto, index_actual))
    return 0;
  else
    return this->get_stat(proto, index_expected) - this->get_stat(proto, index_actual);
} /* End of get_difference() */


double PacketStats::get_percentage(int proto, int index_expected, int index_actual){
  u64 pkts_expected=this->get_stat(proto, index_expected);
  u64 pkts_actual=this->get_stat(proto, index_actual);
  double percent_ok=0.0;
  if(pkts_actual!=0 && pkts_expected!=0)
    percent_ok=((double)pkts_actual)/((double)pkts_expected);
  return percent_ok*100;
} /* End of get_percentage() */


/* Update the stats for tranmitted packets */
int PacketStats::update_sent(int ip_version, int proto, u32 pkt_len){
  return this->update_count(INDEX_SENT, ip_version, proto, pkt_len);
} /* End of update_sent() */


/* Update the stats for received packets */
int PacketStats::update_rcvd(int ip_version, int proto, u32 pkt_len){
  return this->update_count(INDEX_RCVD, ip_version, proto, pkt_len);
} /* End of update_rcvd() */


/* Update the stats for echoed packets (echo mode). */
int PacketStats::update_echoed(int ip_version, int proto, u32 pkt_len){
  return this->update_count(INDEX_ECHOED, ip_version, proto, pkt_len);
} /* End of update_echoed() */


/* Update the stats for the number of packets captured from the wire */
int PacketStats::update_captured(int ip_version, int proto, u32 pkt_len){
  return this->update_count(INDEX_CAPTURED, ip_version, proto, pkt_len);
} /* End of update_captured() */


/** Updates count for echo clients served by the echo server. */
int PacketStats::update_clients_served(){
  this->echo_clients_served++;
  return OP_SUCCESS;
} /* End of update_clients_served() */


/* Update the stats for the number of connections that we have tried to
 * establish. In other words, the number of connect()s calls that we have issued.
 * The "proto" parameter is now redundant but it will make sense if one day
 * we support SCTP connections. */
int PacketStats::update_connects(int ip_version, int proto){
  return this->update_count(INDEX_CONNECTS, ip_version, proto, 0);
} /* End of update_connects() */


/* Update the stats for the number of connections that we have successfully
 * established. The "proto" parameter is now redundant but it will make
 * sense if one day we support SCTP connections. */
int PacketStats::update_accepts(int ip_version, int proto){
  return this->update_count(INDEX_ACCEPTS, ip_version, proto, 0);
} /* End of update_accepts() */


/* Update the stats for the number of unprivileged UDP/TCP read() operations
 * that we have successfully carried out. */
int PacketStats::update_reads(int ip_version, int proto, u32 pkt_len){
  return this->update_count(INDEX_READS, ip_version, proto, pkt_len);
} /* End of update_reads() */


/* Update the stats for the number of unprivileged UDP/TCP read() operations */
int PacketStats::update_writes(int ip_version, int proto, u32 pkt_len){
  return this->update_count(INDEX_WRITES, ip_version, proto, pkt_len);
} /* End of update_writes() */


u64 PacketStats::get_sent(int proto){
  return this->get_stat(proto, INDEX_SENT);
}/* End of get_sent() */


u64 PacketStats::get_rcvd(int proto){
  return this->get_stat(proto, INDEX_RCVD);
}/* End of get_rcvd() */


u64 PacketStats::get_echoed(int proto){
  return this->get_stat(proto, INDEX_ECHOED);
}/* End of get_echoed() */


u64 PacketStats::get_captured(int proto){
  return this->get_stat(proto, INDEX_CAPTURED);
}/* End of get_captured() */


u64 PacketStats::get_reads(int proto){
  return this->get_stat(proto, INDEX_READS);
}/* End of get_reads() */


u64 PacketStats::get_writes(int proto){
  return this->get_stat(proto, INDEX_WRITES);
}/* End of get_writes() */


u64 PacketStats::get_connects(int proto){
  return this->get_stat(proto, INDEX_CONNECTS);
} /* End of get_connects() */


u64 PacketStats::get_accepts(int proto){
  return this->get_stat(proto, INDEX_ACCEPTS);
} /* End of get_accepts() */


/* @warning Assumes that the counter for received packets has NOT been incremented yet. */
int PacketStats::update_rtt(int rtt){
  /* Update Max RTT */
  if(rtt > this->max_rtt || this->max_rtt<0){
    this->max_rtt=rtt;
  }
  /* Update Min RTT */
  if(rtt < this->min_rtt || this->min_rtt<0){
    this->min_rtt=rtt;
  }
  /* Update average RTT */
  if(this->packets[INDEX_RCVD]==0 || this->avg_rtt<0){
    this->avg_rtt = rtt;
  }else{
    this->avg_rtt = ((this->avg_rtt*(this->packets[INDEX_RCVD]))+rtt) / (this->packets[INDEX_RCVD]+1);
  }
  return OP_SUCCESS;
} /* End of update_rtt() */


int PacketStats::start_clocks(){
  this->start_tx_clock();
  this->start_rx_clock();
  return OP_SUCCESS;
} /* End of start_clocks() */


int PacketStats::stop_clocks(){
  this->stop_tx_clock();
  this->stop_rx_clock();
  return OP_SUCCESS;
} /* End of stop_clocks() */


int PacketStats::start_tx_clock(){
  this->tx_timer.start();
  return OP_SUCCESS;
} /* End of start_tx_clock() */


int PacketStats::stop_tx_clock(){
  this->tx_timer.stop();
  return OP_SUCCESS;
} /* End of stop_tx_clock() */

int PacketStats::start_rx_clock(){
  this->rx_timer.start();
  return OP_SUCCESS;
} /* End of start_rx_clock() */


int PacketStats::stop_rx_clock(){
  this->rx_timer.stop();
  return OP_SUCCESS;
} /* End of stop_rx_clock() */


int PacketStats::start_runtime(){
  this->run_timer.start();
  return OP_SUCCESS;
} /* End of start_runtime() */


int PacketStats::stop_runtime(){
  this->run_timer.start();
  return OP_SUCCESS;
} /* End of stop_runtime() */


double PacketStats::get_tx_elapsed(){
  return this->tx_timer.elapsed(NULL);
} /* End of get_tx_elapsed() */


double PacketStats::get_rx_elapsed(){
  return this->rx_timer.elapsed(NULL);
} /* End of get_rx_elapsed() */


double PacketStats::get_runtime_elapsed(struct timeval *now){
  return this->run_timer.elapsed(now);
} /* End of get_runtime_elapsed() */


u64 PacketStats::get_bytes_sent(){
  return this->bytes[INDEX_SENT];
} /* End of get_bytes_sent() */


u64 PacketStats::get_bytes_rcvd(){
  return this->bytes[INDEX_RCVD];
} /* End of get_bytes_rcvd() */


u64 PacketStats::get_bytes_echoed(){
  return this->bytes[INDEX_ECHOED];
} /* End of get_bytes_echoed() */


u64 PacketStats::get_bytes_captured(){
  return this->bytes[INDEX_CAPTURED];
} /* End of get_bytes_captured() */


u64 PacketStats::get_bytes_read(){
  return this->bytes[INDEX_READS];
} /* End of get_bytes_read() */


u64 PacketStats::get_bytes_written(){
  return this->bytes[INDEX_WRITES];
} /* End of get_bytes_written() */


u64 PacketStats::get_lost(int proto){
  return (this->get_sent(proto) <= this->get_rcvd(proto)) ? 0 :
      (this->get_sent(proto) - this->get_rcvd(proto));
}/* End of get_lost() */


double PacketStats::get_percent_lost(int proto){
  /* Only compute percentage if we actually sent packets, don't do divisions
   * by zero! (this could happen when user presses CTRL-C and we print the
   * stats */
  double percentlost=0.0;
  if(this->get_lost(proto)!=0 && this->get_sent(proto)!=0)
    percentlost=((double)this->get_lost(proto))/((double)this->get_sent(proto));
  return percentlost*100;
} /* End of get_percent_lost() */


double PacketStats::get_percent_not_echoed(int proto){
  /* Only compute percentage if we actually sent packets, don't do divisions
   * by zero! (this could happen when user presses CTRL-C and we print the
   * stats */
  u64 not_echoed=this->get_sent(proto)-this->get_echoed(proto);
  double percentlost=0.0;
  if(not_echoed!=0 && this->get_sent(proto)!=0)
    percentlost=((double)not_echoed)/((double)this->get_sent(proto));
  return percentlost*100;
} /* End of get_percent_lost() */


u64 PacketStats::get_clients_served(){
  return this->echo_clients_served;
} /* End of get_clients_served() */


u64 PacketStats::get_connects_failed(int proto){
  /* TCP Connection stats */
  switch(proto){
    case HEADER_TYPE_TCP:
      if(this->tcp[INDEX_CONNECTS] <= this->tcp[INDEX_ACCEPTS])
        return 0;
      else
        return this->tcp[INDEX_CONNECTS] - this->tcp[INDEX_ACCEPTS];
    break;
    default:
      assert(false);
    break;
  }
  return 0;
} /* End of get_accepts() */


double PacketStats::get_percent_failed(int proto){
  u32 pkt_rcvd=this->get_accepts(proto);
  u32 pkt_sent=this->get_connects(proto);
  u32 pkt_lost=(pkt_rcvd>=pkt_sent) ? 0 : (u32)(pkt_sent-pkt_rcvd);
  /* Only compute percentage if we actually sent packets, don't do divisions
   * by zero! (this could happen when user presses CTRL-C and we print the
   * stats */
  double percentlost=0.0;
  if( pkt_lost!=0 && pkt_sent!=0)
    percentlost=((double)pkt_lost)/((double)pkt_sent);
  return percentlost*100;
} /* End of get_percent_lost() */


u64 PacketStats::get_pkts_lost(){
  if(this->packets[INDEX_SENT] <= this->packets[INDEX_RCVD])
    return 0;
  else
    return this->packets[INDEX_SENT] - this->packets[INDEX_RCVD];
} /* End of get_pkts_lost() */


double PacketStats::get_percent_lost(){
  u32 pkt_rcvd=this->packets[INDEX_RCVD];
  u32 pkt_sent=this->packets[INDEX_SENT];
  u32 pkt_lost=(pkt_rcvd>=pkt_sent) ? 0 : (u32)(pkt_sent-pkt_rcvd);
  /* Only compute percentage if we actually sent packets, don't do divisions
   * by zero! (this could happen when user presses CTRL-C and we print the
   * stats */
  double percentlost=0.0;
  if( pkt_lost!=0 && pkt_sent!=0)
    percentlost=((double)pkt_lost)/((double)pkt_sent);
  return percentlost*100;
} /* End of get_percent_lost() */


double PacketStats::get_tx_pkt_rate(){
  double elapsed = this->tx_timer.elapsed(NULL);
  if(elapsed <= 0.0)
    return 0.0;
  else
    return this->packets[INDEX_SENT] / elapsed;
} /* End of get_tx_pkt_rate() */


double PacketStats::get_tx_byte_rate(){
  double elapsed = this->tx_timer.elapsed(NULL);
  if(elapsed <= 0.0)
    return 0.0;
  else
    return this->bytes[INDEX_SENT] / elapsed;
} /* End of get_tx_byte_rate() */


double PacketStats::get_rx_pkt_rate(){
  double elapsed = this->rx_timer.elapsed(NULL);
  if(elapsed <= 0.0)
    return 0.0;
  else
    return this->packets[INDEX_RCVD] / elapsed;
} /* End of get_rx_pkt_rate() */


double PacketStats::get_rx_byte_rate(){
  double elapsed = this->rx_timer.elapsed(NULL);
  if(elapsed <= 0.0)
    return 0.0;
  else
    return this->bytes[INDEX_RCVD] / elapsed;
} /* End of get_rx_byte_rate() */


/* Returns max RTT observed for this host */
int PacketStats::get_max_rtt(){
  return this->max_rtt;
} /* End of get_max_rtt() */


/* Returns min RTT observed for this host */
int PacketStats::get_min_rtt(){
  return this->min_rtt;
} /* End of get_min_rtt() */


/* Returns the average RTT observed for this host */
int PacketStats::get_avg_rtt(){
  return this->avg_rtt;
} /* End of get_avg_rtt() */


/* Print round trip times */
int PacketStats::print_RTTs(const char *leading_str){
  if(leading_str==NULL)
    leading_str="";
  /* Maximum RTT observed */
  if(max_rtt>=0)
    nping_print(VB_0|NO_NEWLINE,"%sMax rtt: %.3lfms ", leading_str, this->get_max_rtt()/1000.0 );
  else
    nping_print(VB_0|NO_NEWLINE,"%sMax rtt: N/A ", leading_str);
  /* Minimum RTT observed */
  if(min_rtt>=0)
    nping_print(VB_0|NO_NEWLINE,"| Min rtt: %.3lfms ", this->get_min_rtt()/1000.0 );
  else
    nping_print(VB_0|NO_NEWLINE,"| Min rtt: N/A " );
  /* Average RTT */
  if(avg_rtt>=0)
    nping_print(VB_0,"| Avg rtt: %.3lfms", this->get_avg_rtt()/1000.0 );
  else
    nping_print(VB_0,"| Avg rtt: N/A" );
  return OP_SUCCESS;
} /* End of print_RTTs() */


int PacketStats::print_proto_stats(int proto, const char *leading_str, bool print_echoed){
  const char *start_str="";
  char auxbuff[256];
  memset(auxbuff, 0, 256);
  if(leading_str==NULL)
    leading_str="";

#ifdef WIN32
 /* TODO: Implement print statements in Windows. We use 64-bit integers and Windows requires the
  * using the %I64u format specifier, instead of %llu */
#else
#endif

  if(proto==STATS_ECHO_SERVER){
    nping_print(QT_1|NO_NEWLINE, "%sRaw packets captured: %llu ", leading_str, this->get_captured(STATS_TOTAL));
    nping_print(QT_1|NO_NEWLINE, "(%s) ", format_bytecount(this->get_bytes_captured(), auxbuff, 256));
    nping_print(QT_1|NO_NEWLINE,"| Echoed: %llu ", this->get_echoed(STATS_TOTAL));
    nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->get_bytes_echoed(), auxbuff, 256));
    nping_print(QT_1|NO_NEWLINE,"| Not Matched: %llu ", this->get_difference(STATS_TOTAL, INDEX_CAPTURED, INDEX_ECHOED));
    nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->get_bytes_captured()-this->get_bytes_echoed(), auxbuff, 256));
    nping_print(QT_1,"(%.2lf%%)", this->get_percentage(STATS_TOTAL, INDEX_CAPTURED, INDEX_ECHOED));
  }else if(proto==STATS_TCP_CONNECT){
    nping_print(QT_1|NO_NEWLINE, "%sTCP connection attempts: %llu ", leading_str, this->get_connects(STATS_TCP));
    nping_print(QT_1|NO_NEWLINE,"| Successful connections: %llu ", this->get_accepts(STATS_TCP));
    nping_print(QT_1|NO_NEWLINE,"| Failed: %llu ", this->get_difference(STATS_TCP, INDEX_CONNECTS, INDEX_ACCEPTS));
    nping_print(QT_1,"(%.2lf%%)", this->get_percentage(STATS_TCP, INDEX_CONNECTS, INDEX_ACCEPTS));
  }else if(proto==STATS_UDP_UNPRIV){
    nping_print(QT_1|NO_NEWLINE, "%sUDP write operations: %llu ", leading_str, this->get_writes(STATS_UDP));
    nping_print(QT_1|NO_NEWLINE,"| Successful reads: %llu ", this->get_reads(STATS_UDP));
    nping_print(QT_1|NO_NEWLINE,"| Failed: %llu ", this->get_difference(STATS_UDP, INDEX_WRITES, INDEX_READS));
    nping_print(QT_1|NO_NEWLINE,"(%.2lf%%)\n", this->get_percentage(STATS_UDP, INDEX_WRITES, INDEX_READS));
  }else{
    switch(proto){
      case STATS_TCP: start_str="TCP"; break;
      case STATS_UDP: start_str="UDP"; break;
      case STATS_ICMPv4: start_str="ICMPv4"; break;
      case STATS_ICMPv6: start_str="ICMPv6"; break;
      case STATS_ARP: start_str="ARP"; break;
      case STATS_IPv4: start_str="IPv4"; break;
      case STATS_IPv6: start_str="IPv6"; break;
      case STATS_TOTAL: start_str="Raw"; break;
      default: assert(0); break;
    }
    nping_print(QT_1|NO_NEWLINE, "%s%s packets sent: %llu ", leading_str, start_str, this->get_sent(proto));
    if(proto==STATS_TOTAL)
      nping_print(QT_1|NO_NEWLINE, "(%s) ", format_bytecount(this->get_bytes_sent(), auxbuff, 256));
    nping_print(QT_1|NO_NEWLINE,"| Rcvd: %llu ", this->get_rcvd(proto));
    if(proto==STATS_TOTAL)
      nping_print(QT_1|NO_NEWLINE,"(%s) ", format_bytecount(this->get_bytes_rcvd(), auxbuff, 256));
    if(print_echoed){
      nping_print(QT_1|NO_NEWLINE,"| Unanswered: %llu ", this->get_difference(proto, INDEX_SENT, INDEX_RCVD));
      nping_print(QT_1|NO_NEWLINE,"(%.2lf%%)", 100 - this->get_percentage(proto, INDEX_SENT, INDEX_RCVD));
      nping_print(QT_1|NO_NEWLINE," | Echoed: %llu ", this->get_echoed(proto));
      nping_print(QT_1|NO_NEWLINE,"(%.2lf%%)", this->get_percentage(proto, INDEX_SENT, INDEX_ECHOED));
    }else{
      nping_print(QT_1|NO_NEWLINE,"| Lost: %llu ", this->get_difference(proto, INDEX_SENT, INDEX_RCVD));
      nping_print(QT_1|NO_NEWLINE,"(%.2lf%%)", 100 - this->get_percentage(proto, INDEX_SENT, INDEX_RCVD));
    }
    nping_print(QT_1|NO_NEWLINE,"\n");
  }
  return OP_SUCCESS;
} /* End of print_proto_stats() */
