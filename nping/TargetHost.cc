
/***************************************************************************
 * NpingTarget.h -- The NpingTarget class encapsulates much of the         *
 * information Nping has about a host. Things like next hop address or the *
 * network interface that should be used to send probes to the target, are *
 * stored in this class as they are determined.                            *
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

#include "TargetHost.h"

TargetHost::TargetHost(){
  this->reset();
} /* End of TargetHost constructor */


TargetHost::~TargetHost(){

} /* End of TargetHost destructor */


void TargetHost::reset(){
  this->target_addr=NULL;
  this->source_addr=NULL;
  this->nxthop_addr=NULL;
  this->target_mac=NULL;
  this->source_mac=NULL;
  this->nxthop_mac=NULL;
  this->net_distance=DISTANCE_UNKONWN;
  this->iface=NULL;
  this->ip4=NULL;
  this->ip6=NULL;
  this->tcp=NULL;
  this->udp=NULL;
  this->icmp4=NULL;
  this->icmp6=NULL;
} /* End of reset() */


int TargetHost::setTargetAddress(IPAddress *addr){
  assert(addr!=NULL);
  this->target_addr=addr;
  return OP_SUCCESS;
} /* End of setTargetAddress() */


IPAddress *TargetHost::getTargetAddress(){
  return this->target_addr;
} /* End of getTargetAddress() */


int TargetHost::setSourceAddress(IPAddress *addr){
  assert(addr!=NULL);
  this->source_addr=addr;
  return OP_SUCCESS;
} /* End of setSourceAddress() */


IPAddress *TargetHost::getSourceAddress(){
  return this->source_addr;
} /* End of getSourceAddress() */


int TargetHost::setNextHopAddress(IPAddress *addr){
  assert(addr!=NULL);
  this->nxthop_addr=addr;
  return OP_SUCCESS;
} /* End of setNextHopAddress() */


IPAddress *TargetHost::getNextHopAddress(){
  return this->nxthop_addr;
} /* End of getNextHopAddress() */


/*Set the network distance to the host. You can pass one of the following values:
 *  - DISTANCE_UNKNOWN to indicate that the distance is not known yet.
 *  - DISTANCE_DIRECT to indicate that the host is directly connected (on-link)
 *  - The number of hops between us and the target, which indicates that the
 *    distance has been determined somehow. */
int TargetHost::setNetworkDistance(int distance){
  this->net_distance=distance;
  return OP_SUCCESS;
} /* End of setNetworkDistance() */


/* Returns the network distance to the host. It can return one of the following
 * values:
 *  - DISTANCE_UNKNOWN if the distance is not known yet.
 *  - DISTANCE_DIRECT if the host is directly connected (on-link)
 *  - a value greater than zero if the distance is know. Such value is obviously
 *    the number of hops between us and the target. */
int TargetHost::getNetworkDistance(){
  return this->net_distance;
} /* End of getNetworkDistance() */


/* Stores the supplied interface information structure inside the object.
 * The information that the structure contains can later be accessed using
 * other helper methods. */
int TargetHost::setInterface(NetworkInterface *val){
  assert(val!=NULL);
  this->iface=val;
  return OP_SUCCESS;
} /* End of setInterface(); */


/* Returns the  a suitable interface to be used when sending packets to the
 * target host. */
NetworkInterface *TargetHost::getInterface(){
  return this->iface;
} /* End of getInterface() */


/* Associates the host with an IPv4 header template. */
int TargetHost::setIPv4(IPv4HeaderTemplate *hdr){
  assert(hdr!=NULL);
  this->ip4=new IPv4HeaderTemplate();
  *this->ip4=*hdr;
  return OP_SUCCESS;
} /* End of setIPv4() */


/* Associates the host with an IPv6 header template. */
int TargetHost::setIPv6(IPv6HeaderTemplate *hdr){
  assert(hdr!=NULL);
  this->ip6=new IPv6HeaderTemplate();
  *this->ip6=*hdr;
  return OP_SUCCESS;
} /* End of setIPv6() */


/* Associates the host with a TCP header template. */
int TargetHost::setTCP(TCPHeaderTemplate *hdr){
  assert(hdr!=NULL);
  this->tcp=new TCPHeaderTemplate();
  *this->tcp=*hdr;
  return OP_SUCCESS;
} /* End of setTCP() */


/* Associates the host with a UDP header template. */
int TargetHost::setUDP(UDPHeaderTemplate *hdr){
  assert(hdr!=NULL);
  this->udp=new UDPHeaderTemplate();
  *this->udp=*hdr;
  return OP_SUCCESS;
} /* End of setUDP() */


/* Associates the host with an ICMPv4 header template. */
int TargetHost::setICMPv4(ICMPv4HeaderTemplate *hdr){
  assert(hdr!=NULL);
  this->icmp4=new ICMPv4HeaderTemplate();
  *this->icmp4=*hdr;
  return OP_SUCCESS;
} /* End of setICMPv4() */


/* Associates the host with an ICMPv6 header template. */
int TargetHost::setICMPv6(ICMPv6HeaderTemplate *hdr){
  assert(hdr!=NULL);
  this->icmp6=new ICMPv6HeaderTemplate();
  *this->icmp6=*hdr;
  return OP_SUCCESS;
} /* End of setICMPv4() */


/* This method inserts whatever packets this TargetHost needs to send into the
 * supplied vector. The number of packets inserted in each call is always the
 * same but it depends on user configuration. If, for example, user passed
 * --tcp and --icmp, then two packets will be inserted in the array for each
 * call. The inserted packets are meant to be sent straight away, or whenever
 * the caller wants, but note that TargetHosts do not keep timing information
 * so the actual transmission rate must be handled externally. This method
 * return OP_SUCCESS on success and OP_FAILURE in case of error. */
int TargetHost::getNextPacketBatch(vector<PacketElement *> &Packets){
  IPv4Header *myip4=NULL;
  IPv6Header *myip6=NULL;
  NetworkLayerElement *myip=NULL;
  TCPHeader *mytcp=NULL;
  UDPHeader *myudp=NULL;
  ICMPv4Header *myicmp4=NULL;
  ICMPv6Header *myicmp6=NULL;
  u16 sum=0, aux=0;

  /* Build a TCP packet */
  if(this->tcp!=NULL){

    mytcp=this->getTCPHeader();

    if(this->ip4!=NULL){
      myip=myip4=this->getIPv4Header("TCP");
      myip4->setNextElement(mytcp);
      myip4->setTotalLength();
      myip4->setSum();

      /* Set a bad IP checksum when appropriate */
      if(this->ip4->csum.getBehavior()==FIELD_TYPE_BADSUM){
        /* Store the correct checksum and pick a different one */
        sum=myip4->getSum();
        while( (aux=get_random_u16())==sum );
        myip4->setSum(aux);
      }else if(this->ip4->csum.is_set()){
        /* This means the user set a specific value, not --badsum-ip */
        myip4->setSum(this->ip4->csum.getNextValue());
      }
    }else if(this->ip6!=NULL){
      myip=myip6=this->getIPv6Header("TCP");
      myip6->setNextElement(mytcp);
      myip6->setPayloadLength();
    }

    /* Set the TCP checksum (or a bad TCP checksum if appropriate) */
    mytcp->setSum();
    if(this->tcp->csum.getBehavior()==FIELD_TYPE_BADSUM){
      /* Store the correct checksum and pick a different one */
      sum=mytcp->getSum();
      while( (aux=get_random_u16())==sum );
      mytcp->setSum(aux);
    }else if(this->tcp->csum.is_set()){
      /* This means the user set a specific value, not --badsum */
      mytcp->setSum(this->tcp->csum.getNextValue());
    }
    /* Once we have the packet ready, insert it into the tx queue */
    Packets.push_back(myip);
  }

  /* Build an UDP packet */
  if(this->udp!=NULL){

    myudp=this->getUDPHeader();

    if(this->ip4!=NULL){
      myip=myip4=this->getIPv4Header("UDP");
      myip4->setNextElement(myudp);
      myip4->setTotalLength();
      myip4->setSum();

      /* Set a bad IP checksum when appropriate */
      if(this->ip4->csum.getBehavior()==FIELD_TYPE_BADSUM){
        /* Store the correct checksum and pick a different one */
        sum=myip4->getSum();
        while( (aux=get_random_u16())==sum );
        myip4->setSum(aux);
      }else if(this->ip4->csum.is_set()){
        /* This means the user set a specific value, not --badsum-ip */
        myip4->setSum(this->ip4->csum.getNextValue());
      }
    }else if(this->ip6!=NULL){
      myip=myip6=this->getIPv6Header("UDP");
      myip6->setNextElement(myudp);
      myip6->setPayloadLength();
    }

    /* Set the UDP checksum (or a bad UDP checksum if appropriate) */
    myudp->setSum();
    if(this->udp->csum.getBehavior()==FIELD_TYPE_BADSUM){
      /* Store the correct checksum and pick a different one */
      sum=myudp->getSum();
      while( (aux=get_random_u16())==sum );
      myudp->setSum(aux);
    }else if(this->udp->csum.is_set()){
      /* This means the user set a specific value, not --badsum */
      myudp->setSum(this->udp->csum.getNextValue());
    }
    /* Once we have the packet ready, insert it into the tx queue */
    Packets.push_back(myip);
  }

  /* Build an ICMPv4 packet */
  if(this->icmp4!=NULL){

    myicmp4=this->getICMPv4Header();
    myip4=this->getIPv4Header("ICMP");
    myip4->setNextElement(myicmp4);
    myip4->setTotalLength();
    myip4->setSum();

    /* Set a bad IP checksum when appropriate */
    if(this->ip4->csum.getBehavior()==FIELD_TYPE_BADSUM){
      /* Store the correct checksum and pick a different one */
      sum=myip4->getSum();
      while( (aux=get_random_u16())==sum );
      myip4->setSum(aux);
    }else if(this->ip4->csum.is_set()){
      /* This means the user set a specific value, not --badsum-ip */
      myip4->setSum(this->ip4->csum.getNextValue());
    }

    /* Set the ICMP checksum (or a bad ICMP checksum if appropriate) */
    myicmp4->setSum();
    if(this->icmp4->csum.getBehavior()==FIELD_TYPE_BADSUM){
      /* Store the correct checksum and pick a different one */
      sum=myicmp4->getSum();
      while( (aux=get_random_u16())==sum );
      myicmp4->setSum(aux);
    }else if(this->icmp4->csum.is_set()){
      /* This means the user set a specific value, not --badsum */
      myicmp4->setSum(this->icmp4->csum.getNextValue());
    }
    /* Once we have the packet ready, insert it into the tx queue */
    Packets.push_back(myip4);
  }

  /* Build an ICMPv6 packet */
  if(this->icmp6!=NULL){

    myicmp6=this->getICMPv6Header();
    myip6=this->getIPv6Header("ICMPv6");
    myip6->setNextElement(myicmp6);
    myip6->setPayloadLength();

    /* Set the ICMP checksum (or a bad ICMP checksum if appropriate) */
    myicmp6->setSum();
    if(this->icmp6->csum.getBehavior()==FIELD_TYPE_BADSUM){
      /* Store the correct checksum and pick a different one */
      sum=myicmp6->getSum();
      while( (aux=get_random_u16())==sum );
      myicmp6->setSum(aux);
    }else if(this->icmp6->csum.is_set()){
      /* This means the user set a specific value, not --badsum */
      myicmp6->setSum(this->icmp6->csum.getNextValue());
    }
    /* Once we have the packet ready, insert it into the tx queue */
    Packets.push_back(myip6);
  }

  return OP_SUCCESS;
} /* End of getNextPacketBatch() */


IPv4Header *TargetHost::getIPv4Header(const char *next_proto){
  IPv4Header *myip4=NULL;
  assert(this->ip4!=NULL);
  myip4=new IPv4Header();
  myip4->setSourceAddress(this->source_addr->getIPv4Address());
  myip4->setDestinationAddress(this->target_addr->getIPv4Address());
  myip4->setTOS(this->ip4->tos.getNextValue());
  myip4->setIdentification(this->ip4->id.getNextValue());
  myip4->setFragOffset(this->ip4->off.getNextValue());
  myip4->setRF(this->ip4->rf.getNextValue());
  myip4->setMF(this->ip4->mf.getNextValue());
  myip4->setDF(this->ip4->df.getNextValue());
  myip4->setTTL(this->ip4->ttl.getNextValue());
  if(this->ip4->nh.is_set()){
    myip4->setNextProto(this->ip4->nh.getNextValue());
  }else if(next_proto!=NULL){
    myip4->setNextProto(next_proto);
  }else{
    myip4->setNextProto("TCP");
  }
  return myip4;
} /* End of getIPv4Header() */


IPv6Header *TargetHost::getIPv6Header(const char *next_proto){
  IPv6Header *myip6=NULL;
  assert(this->ip6!=NULL);
  myip6=new IPv6Header();
  myip6->setSourceAddress(this->source_addr->getIPv6Address());
  myip6->setDestinationAddress(this->target_addr->getIPv6Address());
  myip6->setHopLimit(this->ip6->hlim.getNextValue());
  if(this->ip6->nh.is_set()){
    myip6->setNextHeader(this->ip6->nh.getNextValue());
  }else if(next_proto!=NULL){
    myip6->setNextHeader(next_proto);
  }else{
    myip6->setNextHeader("TCP");
  }
  return myip6;
} /* End of getIPv6Header() */


TCPHeader *TargetHost::getTCPHeader(){
  TCPHeader *mytcp=NULL;
  assert(this->tcp!=NULL);
  mytcp=new TCPHeader();
  mytcp->setSourcePort(this->tcp->sport.getNextValue());
  mytcp->setDestinationPort(this->tcp->dport.getNextValue());
  mytcp->setSeq(this->tcp->seq.getNextValue());
  mytcp->setAck(this->tcp->ack.getNextValue());
  mytcp->setOffset(this->tcp->off.getNextValue());
  mytcp->setFlags(this->tcp->flags.getNextValue());
  mytcp->setWindow(this->tcp->win.getNextValue());
  mytcp->setUrgPointer(this->tcp->urp.getNextValue());
  return mytcp;
} /* End of getTCPHeader() */


UDPHeader *TargetHost::getUDPHeader(){
  UDPHeader *myudp=NULL;
  assert(this->udp!=NULL);
  myudp=new UDPHeader();
  myudp->setSourcePort(this->udp->sport.getNextValue());
  myudp->setDestinationPort(this->udp->dport.getNextValue());
  return myudp;
} /* End of getTCPHeader() */


ICMPv4Header *TargetHost::getICMPv4Header(){
  ICMPv4Header *myicmp4=NULL;
  assert(this->icmp4!=NULL);
  myicmp4=new ICMPv4Header();

  myicmp4->setType(this->icmp4->type.getNextValue());
  myicmp4->setCode(this->icmp4->code.getNextValue());

  switch(myicmp4->getType()){

    case ICMP_REDIRECT:
      myicmp4->setGatewayAddress(this->icmp4->redir_addr.getNextValue() );
    break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
    case ICMP_DOMAINNAME:
    case ICMP_DOMAINNAMEREPLY:
      myicmp4->setIdentifier(this->icmp4->id.getNextValue());
      myicmp4->setSequence(this->icmp4->seq.getNextValue());
    break;

    case ICMP_ROUTERADVERT:
      myicmp4->setAddrEntrySize(2);
      myicmp4->setLifetime(this->icmp4->lifetime.getNextValue());

      /* TODO @todo Implement advert entries! */
      //if(o.issetICMPAdvertEntry()){
      //  for (int z=0; z<o.getICMPAdvertEntryCount(); z++){
      //    struct in_addr entryaddr;
      //    u32 entrypref;
      //    o.getICMPAdvertEntry(z, &entryaddr, &entrypref );
      //    myicmp4->addRouterAdvEntry(entryaddr, entrypref);
      //   }
      //}
    break;

    case ICMP_PARAMPROB:
        myicmp4->setParameterPointer(this->icmp4->pointer.getNextValue());
    break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
      myicmp4->setIdentifier(this->icmp4->id.getNextValue());
      myicmp4->setSequence(this->icmp4->seq.getNextValue());
      myicmp4->setOriginateTimestamp(this->icmp4->ts_orig.getNextValue());
      myicmp4->setReceiveTimestamp(this->icmp4->ts_rx.getNextValue());
      myicmp4->setTransmitTimestamp(this->icmp4->ts_tx.getNextValue());
    break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
      myicmp4->setIdentifier(this->icmp4->id.getNextValue());
      myicmp4->setSequence(this->icmp4->seq.getNextValue());
      myicmp4->setAddressMask(this->icmp4->mask.getNextValue());
    break;

    case ICMP_TRACEROUTE:
    case ICMP_UNREACH:
    case ICMP_SOURCEQUENCH:
    case ICMP_ROUTERSOLICIT:
    case ICMP_TIMXCEED:
    break;

    default:
      /* TODO: What do we do here if user specified a non standard type? */
    break;

  }

  return myicmp4;
} /* End of getICMPv4Header() */






ICMPv6Header *TargetHost::getICMPv6Header(){
  ICMPv6Header *myicmp6=NULL;
  assert(this->icmp6!=NULL);
  myicmp6=new ICMPv6Header();

  myicmp6->setType(this->icmp6->type.getNextValue());
  myicmp6->setCode(this->icmp6->code.getNextValue());

  switch(myicmp6->getType()){

    case ICMPv6_ECHO:
    case ICMPv6_ECHOREPLY:
      myicmp6->setIdentifier(this->icmp6->id.getNextValue());
      myicmp6->setSequence(this->icmp6->seq.getNextValue());
    break;

    case ICMPv6_PKTTOOBIG:
      myicmp6->setMTU(this->icmp6->mtu.getNextValue());
    break;

    case ICMPv6_PARAMPROB:
      myicmp6->setPointer(this->icmp6->pointer.getNextValue());
    break;

    case ICMPv6_UNREACH:
    case ICMPv6_TIMXCEED:

    case ICMPv6_GRPMEMBQUERY:
    case ICMPv6_GRPMEMBREP:
    case ICMPv6_GRPMEMBRED:
    case ICMPv6_ROUTERSOLICIT:
    case ICMPv6_ROUTERADVERT:
    case ICMPv6_NGHBRSOLICIT:
    case ICMPv6_NGHBRADVERT:
    case ICMPv6_REDIRECT:
    case ICMPv6_RTRRENUM:
    case ICMPv6_NODEINFOQUERY:
    case ICMPv6_NODEINFORESP:
    case ICMPv6_INVNGHBRSOLICIT:
    case ICMPv6_INVNGHBRADVERT:
    case ICMPv6_MLDV2:
    case ICMPv6_AGENTDISCOVREQ:
    case ICMPv6_AGENTDISCOVREPLY:
    case ICMPv6_MOBPREFIXSOLICIT:
    case ICMPv6_MOBPREFIXADVERT:
    case ICMPv6_CERTPATHSOLICIT:
    case ICMPv6_CERTPATHADVERT:
    case ICMPv6_EXPMOBILITY:
    case ICMPv6_MRDADVERT:
    case ICMPv6_MRDSOLICIT:
    case ICMPv6_MRDTERMINATE:
    case ICMPv6_FMIPV6:

    default:
      /* TODO: What do we do here if user specified a non standard type? */
    break;

  }

  return myicmp6;
} /* End of getICMPv6Header() */
