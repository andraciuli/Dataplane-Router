#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#define ICMP_PROTOCOL 1
#define ECHO_REQUEST 8
#define ECHO_REPLY 0
#define DEST_UNREACHABLE 3
#define TIME_EXCEEDED 11
#define ETHERTYPE_IP 0x0800

int rtable_size;	// the number of lines in the routing table
struct route_table_entry *rtable;

int arptable_size;	// the number of lines in the arp table
struct arp_table_entry *arptable;

static inline int32_t comparator(const void *p, const void *q)
{
	struct route_table_entry *route1 = (struct route_table_entry *)p;
	struct route_table_entry *route2 = (struct route_table_entry *)q;

	// Compare prefixes
    if (ntohl(route1->prefix) > ntohl(route2->prefix)) {
		return 1;
	} else if (ntohl(route1->prefix) < ntohl(route2->prefix)) {
		return -1;
	}
    
    // Prefixes are equal, compare masks
    if (ntohl(route1->mask) > ntohl(route2->mask)) {
		return 1;
	} else if (ntohl(route1->mask) < ntohl(route2->mask)) {
		return -1;
	}

    // Both prefix and mask are equal
    return 0;
}

struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	struct route_table_entry *best_route = NULL;
    int left = 0;
    int right = rtable_size - 1;

    while (left <= right) {
        int middle = left + (right - left) / 2;

		if (!best_route) {
			if ((ip_dest & rtable[middle].mask) == rtable[middle].prefix) {
				best_route = &rtable[middle];
			}
		} else {
			if ((ip_dest & rtable[middle].mask) == rtable[middle].prefix) {
				if (ntohl(best_route->mask) < ntohl(rtable[middle].mask)) {
					best_route = &rtable[middle];
				}
			}
		}

        if (ntohl(rtable[middle].prefix) >= ntohl(ip_dest)) {
			right = middle - 1;
        } else {
            left = middle + 1;
        }
    }

    return best_route;
}


struct arp_table_entry *get_mac_entry(uint32_t given_ip)
{
	for (int i = 0; i < arptable_size; i++) {
		if (arptable[i].ip == given_ip) {
			return &arptable[i];
		}	
	}

	return NULL;
}

void generate_icmp(char *buf, int interface, size_t len, int type)
{
	struct ether_header *pack_eth_hdr = (struct ether_header *)buf;
	struct iphdr *pack_ip_hdr = (struct iphdr *)(buf + sizeof(*pack_eth_hdr));
	struct icmphdr *pack_icmp_hdr = (struct icmphdr *)(buf + sizeof(*pack_eth_hdr) + sizeof(*pack_ip_hdr));

	// Check if the packet is an echo request
	if (type == ECHO_REPLY) {
		// if the protocol is not icmp drop the packet or
		// if the type of the received message is not echo request drop the packet
		if (pack_ip_hdr->protocol != ICMP_PROTOCOL || pack_icmp_hdr->type != ECHO_REQUEST) {
			return;
		}		
	}

	// Create Ethernet header
	uint8_t  ether_shost_aux[6];
	memcpy(ether_shost_aux, pack_eth_hdr->ether_shost, 6);
	memcpy(pack_eth_hdr->ether_shost, pack_eth_hdr->ether_dhost, 6);
	memcpy(pack_eth_hdr->ether_dhost, ether_shost_aux, 6);

	// Create payload
	int payload_len;
	if (type == ECHO_REPLY) {
		payload_len = len - sizeof(struct ether_header) -
			sizeof(struct iphdr) - sizeof(struct icmphdr);
	} else {
		if (len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr) < 64) {
			payload_len = len - sizeof(struct ether_header) -
			sizeof(struct iphdr) - sizeof(struct icmphdr);
		} else {
			payload_len = len - sizeof(struct ether_header) -
			sizeof(struct iphdr) - sizeof(struct icmphdr) + 64;
		}
	}
	// Create IP header
	// Swap source and destination
	uint32_t aux_saddr = pack_ip_hdr->saddr;
	pack_ip_hdr->saddr = pack_ip_hdr->daddr;
	pack_ip_hdr->daddr = aux_saddr;
	pack_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
	pack_ip_hdr->protocol = ICMP_PROTOCOL;
	// Reset checksum
	pack_ip_hdr->check = 0;
	pack_ip_hdr->check = htons(checksum((void *)pack_ip_hdr, sizeof(struct iphdr)));

	// Create ICMP header 
	pack_icmp_hdr->type = type;
	pack_icmp_hdr->code = 0;

	memcpy(buf + sizeof(struct ether_header) +
				   sizeof(struct iphdr) + sizeof(struct icmphdr),
			   pack_icmp_hdr + sizeof(struct icmphdr), payload_len);

	pack_icmp_hdr->checksum = 0;
	pack_icmp_hdr->checksum = htons(checksum((void *)pack_icmp_hdr, sizeof(struct icmphdr) + payload_len));

	send_to_link(interface, buf, sizeof(struct ether_header) +
		sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "memory allocation failed");
	rtable_size = read_rtable(argv[1],rtable);

	qsort(rtable, rtable_size, sizeof(rtable[0]), comparator);

	arptable = malloc(sizeof(struct arp_table_entry) * 80000);
	DIE(arptable == NULL, "memory allocation failed");
	arptable_size = parse_arp_table("arp_table.txt", arptable);


	while (1) {

		int interface;
		size_t len;

		// Receive packets
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_link failed");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		// Check if we got an IPv4 packet
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			// Ignore non-IPv4 packets
			continue;
		}

		uint16_t old_checksum = ip_hdr->check;
		ip_hdr->check = 0;
		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != ntohs(old_checksum)) {
			// Ignored packet with bad checksum
			continue;
		}

		// Check if the packet is for us
		if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
			// Send ICMP echo reply
			generate_icmp(buf, interface, len, ECHO_REPLY);
			continue;
		}

		struct route_table_entry *best_router = get_best_route(ip_hdr->daddr);
		// Destination unreachable
		if (best_router == NULL) {
			// Send ICMP destination unreachable
			generate_icmp(buf, interface, len, DEST_UNREACHABLE);
			continue;
		}

		// Time exceeded
		if (ip_hdr->ttl <= 1) {
			// Send ICMP time exceeded
			generate_icmp(buf, interface, len, TIME_EXCEEDED);
			continue;
		}

		// Decrement TTL
		ip_hdr->ttl--;
		// Reset checksum
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		// Update MAC addresses
		struct arp_table_entry *mac_entry = get_mac_entry(best_router->next_hop);
		if (mac_entry == NULL) {
			continue;
		}

		memcpy(eth_hdr->ether_dhost, mac_entry->mac, sizeof(eth_hdr->ether_dhost));
		get_interface_mac(best_router->interface, eth_hdr->ether_shost);
		send_to_link(best_router->interface, buf, len);
	}

	free(rtable);
	free(arptable);
	return 0;
}
