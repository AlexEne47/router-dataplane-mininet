#include "queue.h"
#include "list.h"
#include "skel.h"
#include <stdlib.h>

#define ARP 0x0806

struct route_table_entry *r_table;
int r_table_len;
struct arp_entry *arp_table;
int arp_table_len = 0;

// Cautare binara in tabela de rutare
struct route_table_entry *get_br_binary(struct in_addr dest_ip) {
	struct route_table_entry *result = NULL;
	int low = 0;
	int high = r_table_len - 1;
	int mid;

	while(low <= high) {
		mid = (low + high) / 2;

		uint32_t dest_ip_masked = dest_ip.s_addr & r_table[mid].mask;
		uint32_t network_ip = r_table[mid].prefix;

		if(network_ip > dest_ip_masked)
		high = mid - 1;
		else if(network_ip < dest_ip_masked)
		low = mid + 1;
		else if(network_ip == dest_ip_masked) {
			result = &r_table[mid];
			low = mid + 1;
		}
	}

	return result;
}

// Sortam tabela dupa masca iar la final dupa prefix 
int compare_table(const void *a, const void *b) {
	struct route_table_entry *el1= (struct route_table_entry *)a;
	struct route_table_entry *el2 = (struct route_table_entry *)b;

	if(el1->mask == el2->mask) 
	return el1->prefix - el2->prefix; 
	else 
	return el2->mask - el1->mask;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Extragem tabela de rutare
	r_table = (struct route_table_entry *)malloc(100000*sizeof(struct route_table_entry));
	DIE(r_table == NULL, "r_table fail");
	r_table_len = read_rtable(argv[1],r_table);
	DIE(r_table_len < 0, "read_table fail \n");

	// Aloc memorie pentru intrarile din tabela ARP
	arp_table = (struct arp_entry *)malloc(10*sizeof(struct arp_entry));
	arp_table_len = 0;

	// Sortez tabela folosind qsort 
	qsort(r_table, r_table_len, sizeof(struct route_table_entry), compare_table);

	// Creez coada de packete
	queue coada_packete;
	coada_packete = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		struct ether_header *eth_hdr = (struct ether_header *) m.payload;

		// Preiau ip-ul interfetei curente
		struct sockaddr_in this_ip;
		inet_pton(AF_INET, get_interface_ip(m.interface), &(this_ip.sin_addr));

		// Preluam mac-ul interfetei curente
		uint8_t mac[6], broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		get_interface_mac(m.interface, mac);

		if (ntohs(eth_hdr->ether_type) == ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

			// ARP reply
			if(ntohs(arp_hdr->op) == 2) {

				// Daca nu este pentru noi, ii dam forward
				if(arp_hdr->tpa != this_ip.sin_addr.s_addr) {
					struct in_addr d;
					d.s_addr = arp_hdr->tpa;

					struct route_table_entry *best_route = get_br_binary(d);
					if(best_route == NULL) 
					continue;

					m.interface = best_route->interface;
					send_packet(&m);
					continue;
				}
				
				// Adaugam intrarea in tabela ARP
				arp_table[arp_table_len].ip = arp_hdr->spa;
				memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, 6);
				arp_table_len++;

				// Trecem prin coada de packete si vedem
				// ce packete avem de trimis
				queue temp = queue_create();

				while(!queue_empty(coada_packete)) {
					packet aux = *(packet *)queue_deq(coada_packete);

					struct ether_header *eth_hdr = (struct ether_header *) aux.payload;

					if(inet_addr(get_interface_ip(aux.interface)) == arp_hdr->tpa) {
						get_interface_mac(aux.interface, eth_hdr->ether_shost);
						memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6);
						send_packet(&aux);
					}
					else {
						queue_enq(temp, (void *)&aux);
					}
				}

				// Coada initiala devine cea noua
				free(coada_packete);
				coada_packete = temp;

				continue;
			}

			// ARP request
			if((htons(arp_hdr->op) == 1)) {

				// Daca nu este pentru noi il trimitem mai departe
				if(arp_hdr->tpa != this_ip.sin_addr.s_addr) {
					struct in_addr d;
					d.s_addr = arp_hdr->tpa;

					struct route_table_entry *best_route = get_br_binary(d);
					if(best_route == NULL) 
					continue;
					
					send_packet(&m);
					continue;
				}
				else { 
				// Este pentru noi
				// Creeam ARP reply

				arp_hdr->op = htons(2);
				uint32_t aux = arp_hdr->tpa;

				arp_hdr->tpa = arp_hdr->spa;
				memcpy(arp_hdr->tha, arp_hdr->sha, 6);

				arp_hdr->spa = aux;
				memcpy(arp_hdr->sha, mac, 6);

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr->ether_shost, mac, 6);

				send_packet(&m);
				continue;
				}
			}

			continue;
		}
		else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

			// Extrag headerele IP si ICMP
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

			// Verificam checksum-ul
			uint16_t saved_check = ip_hdr->check;
			ip_hdr->check = 0;
			if(saved_check != ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr)))
			continue;

			ip_hdr->check = saved_check;

			if(ip_hdr->protocol != 1) {
			ip_hdr->protocol = 1;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));
			}

			// Daca TTL <= 1 returnam ICMP Type 11
			if(ip_hdr->ttl <= 1) {
				icmp_hdr->type = ICMP_TIME_EXCEEDED;
				icmp_hdr->code = 0;

				ip_hdr->protocol = 1;

				m.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				memcpy(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), 
				m.payload, 
				8);

				// Inversez adresele IP
				uint32_t temp = ip_hdr->daddr;
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = temp;

				// Adresa eth_dhost este eth_shost
				// iar eth_shost devine adresa interfetei pe care a venit
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr->ether_shost, mac, 6);

				// Recalculez checksum pentru ip si icmp
				ip_hdr->tot_len = htons(20 + 8 + 8);
				ip_hdr->check = 0;
				icmp_hdr->checksum = 0;
				ip_hdr->ttl = 64;

				ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));
				icmp_hdr->checksum = icmp_checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));

				rc = send_packet(&m);
				DIE(rc < 0, "send_packet");

				continue;
			}

			// Cautam adresa pentru next hop
			struct in_addr dest_addr;
			dest_addr.s_addr = ip_hdr->daddr;

			struct route_table_entry *best_route;
			best_route = get_br_binary(dest_addr);	

			// Daca nu gasim next hop returnam ICMP Type 3
			if(best_route == NULL) {
				icmp_hdr->type = ICMP_DEST_UNREACH;
				icmp_hdr->code = 0;

				ip_hdr->protocol = 1;

				m.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				memcpy(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), 
				m.payload, 
				8);

				// Inversez adresele IP
				uint32_t temp = ip_hdr->daddr;
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = temp;

				// Adresa eth_dhost este eth_shost
				// iar eth_shost devine adresa interfetei pe care a venit
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr->ether_shost, mac, 6);

				// Recalculez checksum pentru ip si icmp
				ip_hdr->tot_len = htons(20 + 8 + 8);
				ip_hdr->check = 0;
				icmp_hdr->checksum = 0;
				ip_hdr->ttl = 64;

				ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));
				icmp_hdr->checksum = icmp_checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));

				rc = send_packet(&m);
				DIE(rc < 0, "send_packet");

				continue;
			}

			dest_addr.s_addr = best_route->next_hop;

			// Decrementam TTL
			// Actualizare checksum optim (conform RFC1624)
			uint16_t old_ttl, mask = 0xffff;
			uint32_t new_sum;

			old_ttl = ntohs(ip_hdr->ttl);
			ip_hdr->ttl--;
			new_sum = (~ntohs(ip_hdr->ttl) & mask) + old_ttl;
			new_sum += ntohs(ip_hdr->check);
			new_sum = (new_sum >> 16) + (new_sum & mask);
			new_sum = htons(new_sum + (new_sum >> 16));
			ip_hdr->check = new_sum;

			// Modific campurile pentru ICMP Echo 
			if(ip_hdr->daddr == this_ip.sin_addr.s_addr) {
			icmp_hdr->type = 0;
			icmp_hdr->code = 0;

			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = icmp_checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));
			}
			
			// Cautam adresa MAC a next hop in tabela ARP
			int gasit = 0;
			for(int i=0; i<arp_table_len; i++) {
				struct in_addr d;
				char addr[50];
				d.s_addr = arp_table[i].ip;
				strcpy(addr,inet_ntoa(d));

				if(best_route->next_hop == arp_table[i].ip) {//daca gasim
				memcpy(eth_hdr->ether_dhost, arp_table[i].mac, 6);
				gasit = 1;
				}
			}

			// Daca nu gasim adresa, generam un ARP request
			if(!gasit) { 

				packet arp_request;
				arp_request.len = sizeof(struct ether_header) + sizeof(struct arp_header);
				arp_request.interface = best_route->interface;

				struct ether_header *arp_request_eth = malloc(sizeof(struct ether_header));
				struct arp_header *arp_request_arp = malloc(sizeof(struct arp_header));

				arp_request_eth->ether_type = htons(0x0806);

				uint8_t best_route_mac[6];
				get_interface_mac(best_route->interface,best_route_mac);

				struct sockaddr_in best_route_ip;
				inet_pton(AF_INET, get_interface_ip(best_route->interface), &(best_route_ip.sin_addr));

				memcpy(arp_request_eth->ether_dhost, broadcast, 6);
				memcpy(arp_request_eth->ether_shost, best_route_mac, 6);

				arp_request_arp->htype = htons(1);
				arp_request_arp->ptype = htons(2048);
				arp_request_arp->hlen = 6;
				arp_request_arp->plen = 4;
				arp_request_arp->op = htons(1);
				
				memcpy(arp_request_arp->sha, best_route_mac, 6);
				arp_request_arp->spa = best_route_ip.sin_addr.s_addr;
				memcpy(arp_request_arp->tha, broadcast, 6);
				arp_request_arp->tpa = best_route->next_hop;

				// Copiem in packet
				memcpy(arp_request.payload, arp_request_eth, sizeof(struct ether_header));
				memcpy(arp_request.payload + sizeof(struct ether_header), arp_request_arp, sizeof(struct arp_header));

				// Trimitem packet-ul
				send_packet(&arp_request);

				// Creez o copie a packet-ului 
				packet m1;
				m1.interface = best_route->interface; 
				m1.len = m.len;
				memcpy(m1.payload, m.payload, sizeof(m.payload));

				// Adaug packet-ul in coada
				queue_enq(coada_packete, (void *)&m1);

				continue;
			}

			// Copiez adresa in header si acualizez interfata
			get_interface_mac(best_route->interface,eth_hdr->ether_shost);
			m.interface = best_route->interface;

			rc = send_packet(&m);
			DIE(rc < 0, "send_packet");
		}
		else {
			// Ii dam drop 
			continue;
		}

	}
}
