/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
	
	struct sr_packet *current;
	current = req->packets;
	while(current != NULL) {
		uint8_t *header_buffer = (uint8_t *)malloc(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
		memcpy(header_buffer, current->buf, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
		/*CREATE ICMP*/
		sr_icmp_t3_hdr_t * icmp_header = (sr_icmp_t3_hdr_t *)(header_buffer + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_header->icmp_code = 1;
		icmp_header->icmp_type = 3;
		icmp_header->icmp_sum = 0;
		icmp_header->next_mtu = IP_MAXPACKET;
		icmp_header->icmp_sum = cksum(icmp_header, current->len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));  
		/*FIX IP PACKET*/
		sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(header_buffer + sizeof(sr_ethernet_hdr_t));
		ip_header->ip_dst = ip_header->ip_src;
		ip_header->ip_p = htons(ip_protocol_icmp);		
		char* interface_name = (char *)(malloc(sizeof(char) * sr_IFACE_NAMELEN));
		struct sr_if *current_interface = sr_get_interface(sr, interface_name);
		ip_header->ip_src = current_interface->ip;
		ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * 4);/*should be * 4 but not sure*/
		/*UPDATE ETHERNET FRAME*/
		sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)(header_buffer);
		memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
		memcpy(ethernet_header->ether_shost, current_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
		ethernet_header->ether_type = htons(ethertype_ip);
		sr_send_packet(sr, header_buffer, (sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t)), interface_name);
		free(header_buffer);
		free(interface_name);
		/*free more things?*/
		current = current->next;	
		
	}
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
     /* packets waiting on this request         */

      sr_arpreq_destroy(&(sr->cache), req);
    }
	
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
	struct sr_packet *packet = req->packets;
	while(packet != NULL) {
		sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)(packet->buf);
		memcpy(ethernet_header->ether_dhost, arphdr->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
		memcpy(ethernet_header->ether_shost, src_iface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
		
		/*TODO: decrement TTL of ip header*/
		sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet->buf+sizeof(sr_ip_hdr_t));
		ip_header->ip_ttl--; /*Not sure if this works */
		/*TODO: redo checksum*/
		ip_header->ip_sum = cksum(ip_header, packet->len-sizeof(sr_ethernet_hdr_t));
		sr_send_packet(sr, packet->buf, packet->len,packet->iface);
		packet = packet->next;
	}
	/*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */
	
      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

/*
 *Creating ICMP messages
 * TODO: fix first todo to use this?
 *
 *
 *
 *
 *
 */
void sr_create_icmp_message(struct sr_instance *sr, int type, int code, uint8_t *packet, int len, struct sr_if *interface) {
	uint8_t *header_buffer;
	int size;
	sr_icmp_t3_hdr_t *icmp_header;
	switch(type) {
		case 3:
		case 11:
			size = sizeof(sr_icmp_t3_hdr_t);
			header_buffer = (uint8_t*)malloc(sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t));
			memcpy(header_buffer, packet, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

			icmp_header = (sr_icmp_t3_hdr_t *)(header_buffer + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
			icmp_header->icmp_code = code;
			icmp_header->icmp_type = type;
			icmp_header->next_mtu = IP_MAXPACKET;
			memcpy(icmp_header->data, packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
			icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));		
			break;
		case 0: 
			header_buffer = (uint8_t*)malloc(len);
			memcpy(header_buffer,packet,len);
			icmp_header = (sr_icmp_t3_hdr_t *)(header_buffer + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));	
			icmp_header->icmp_code = code;
			icmp_header->icmp_type = type;
			icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_hdr_t));
			size = len - (sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
			break;
		default:
			size = sizeof(sr_icmp_hdr_t);
			header_buffer = (uint8_t*)malloc(sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
			memcpy(header_buffer, packet, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
			icmp_header = (sr_icmp_t3_hdr_t *)(header_buffer + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
			icmp_header->icmp_type = type;
			icmp_header->icmp_code = code;
			icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_hdr_t));	 	
			break;
	}
	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(header_buffer + sizeof(sr_ethernet_hdr_t));
	ip_header->ip_dst = ip_header->ip_src;
	ip_header->ip_ttl = 64;
	ip_header->ip_src = interface->ip;
	ip_header->ip_p = ip_protocol_icmp;
	ip_header->ip_len = htons(sizeof(sr_ip_hdr_t)+size);
	ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * 4);
	sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)(header_buffer);
	memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost,sizeof(uint8_t) * ETHER_ADDR_LEN);	
	memcpy(ethernet_header->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
	ethernet_header->ether_type = htons(ethertype_ip);
	sr_send_packet(sr, header_buffer, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+size, interface->name);
	free(header_buffer);
}

/*-------------------------------------------------------------------------
 * Method: sr_handlepacket_ip
 * Scope: Global
 * Hanldes ip packets
 *-------------------------------------------------------------------------*/

void sr_handlepacket_ip(struct sr_instance* sr,
	uint8_t * packet,
	unsigned int len,
	char* interface)
{
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
 /*TODO: make sure its a valid ip  packet */

	if(ip_header->ip_sum != cksum(ip_header, ip_header->ip_hl * 4))
		return;
			
 /*TODO: handle */
	/*TODO: handle if packet is for me*/
	int sent_to_us = 0;
	struct sr_if *inter = sr->if_list;
	while(inter != NULL) {
		if(ip_header->ip_dst == inter->ip)
			sent_to_us = 1;
		inter = inter->next;
	}
		ip_header->ip_ttl--;
		if(ip_header->ip_ttl == 0) {
			sr_create_icmp_message(sr, 11, 0, packet, len, sr_get_interface(sr, interface));
			return;		
		}
	if(sent_to_us == 1) {
		
		sr_icmp_t3_hdr_t *icmp_header;
		switch(ip_header->ip_p) {
		case 1: 
			icmp_header = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
			if(icmp_header->icmp_type==8&& icmp_header->icmp_sum == cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)))
				sr_create_icmp_message(sr, 8, 0, packet, len, sr_get_interface(sr, interface));
		break;
		case 17:
			sr_create_icmp_message(sr, 3, 3, packet, len, sr_get_interface(sr, interface));
			break;
		case 6:
			sr_create_icmp_message(sr, 3, 3, packet, len, sr_get_interface(sr, interface));
			break;
		default:
			break;
		}
	}
	else { /** forward the packet because its not ours **/
		struct sr_rt *next_hop =sr_longest_prefix_match(sr, ip_header->ip_dst); /** find longest prefix match**/
		if(next_hop == NULL) {
			sr_create_icmp_message(sr, 3, 0,packet, len, sr_get_interface(sr, interface));
			return;
		}
		struct sr_arpentry *arp_cached = sr_arpcache_lookup(&(sr->cache),(next_hop->dest).s_addr);
		if(!arp_cached) { /*do arp request */ 
			sr_waitforarp(sr, packet, len, (next_hop->dest).s_addr, sr_get_interface(sr, next_hop->interface));
		}		
		else {
			struct sr_if *inter_out = sr_get_interface(sr, interface);
			memcpy(ethernet_header->ether_shost, inter_out->addr, sizeof(char)* ETHER_ADDR_LEN);
			memcpy(ethernet_header->ether_dhost, arp_cached->mac, sizeof(char)* ETHER_ADDR_LEN);;
			sr_send_packet(sr, packet, len, (char *)malloc(sizeof(char) *sr_IFACE_NAMELEN));
			free(arp_cached);
		}
	}
	/*TODO: handle if packet is to be forwarded*/	

}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*************************************************************************/
  /* TODO: Handle packets                                                  */
	if(len >= sizeof(struct sr_ethernet_hdr)){
		if(ethertype(packet) == ethertype_ip) /*use switch with ntohs if doesnt worK?*/
			sr_handlepacket_ip(sr, packet,len, interface);
		else
			sr_handlepacket_arp(sr, packet,len,sr_get_interface(sr, interface));
	}

  /*************************************************************************/

}/* end sr_ForwardPacket */


