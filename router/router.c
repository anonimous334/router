#include <stdlib.h>
#include "skel.h"
#include "queue.h"
#include "list.h"

int interfaces[ROUTER_NUM_INTERFACES];
u_char BROADCAST_MAC[] = {-1,-1,-1,-1,-1,-1};

struct route_table_entry *r_tabela;
struct arp_table *arp_tabela;
int rtable_size;
int arp_table_len;
int arp_table_max_len;

uint16_t ip_checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;
	uint64_t acc=0xffff;
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}
	return htons(~acc);
}
int func(const void * a, const void * b) {
	return ((struct route_table_entry*)a)->prefix - ((struct route_table_entry*)b)->prefix;
}
void read_rtable(struct route_table_entry tabela[64000]) {
	FILE *f;
	fprintf(stderr, "Read rtable\n");
	f = fopen("rtable.txt", "r");
	DIE(f == NULL, "Failed to open rtable.txt");
	char line[160];
	int i;

	for(i = 0; fgets(line, sizeof(line), f); i++) {
		char prefix[50], next_hop[50], mask[50];
		uint32_t interface;
		sscanf(line, "%s %s %s %d", prefix, next_hop, mask, &interface);
		tabela[i].prefix = inet_addr(prefix);
		tabela[i].next_hop = inet_addr(next_hop);
		tabela[i].mask = inet_addr(mask);
		tabela[i].interface = interface;
		rtable_size += 1;
	}
	qsort(tabela, i, sizeof(tabela[i]), func);
	r_tabela = tabela;
}
void add_in_arp_table(uint32_t ip, u_char mac[6]) {
	int i = 0;
	if(arp_table_len == arp_table_max_len) {
		struct arp_table new_table[2*arp_table_max_len];
		arp_table_max_len *= 2;
		for(i = 0; i < arp_table_len; i++) {
			new_table[i] = arp_tabela[i];
		}
		arp_tabela = new_table;
	}

	for(i = arp_table_len - 1; (i >= 0 && arp_tabela[i].ip > ip); i--) {
		arp_tabela[i+1] = arp_tabela[i];
	}
	arp_tabela[i+1].ip = ip;
	memcpy(arp_tabela[i+1].mac, mac, 6);
	arp_table_len += 1;
}
int CautareArptable(int l, int h, uint32_t next_hop) {
	int mid = 0;
	while(l <= h) {
		mid = (l + h) / 2;
		if(next_hop < arp_tabela[mid].ip) {
			h = mid - 1;
		} else if(next_hop > arp_tabela[mid].ip) {
			l = mid + 1;
		} else {
			return mid;
		}
	}
	return -1;
}
int CautareRtable(int l, int h, uint32_t ip) {
	int mid = 0;
	while(l <= h) {
		mid = (l + h) / 2;
		uint32_t daddr = ip & r_tabela[mid].mask;
		if(daddr < r_tabela[mid].prefix) {
			h = mid - 1;
		} else if(daddr > r_tabela[mid].prefix) {
			l = mid + 1;
		} else {
			while((ip & r_tabela[mid + 1].mask) == r_tabela[mid + 1].prefix) {
				mid++;
			}
			return mid;
		}
	}
	return -1;
}
void transmitePachet(packet p, u_char dest_ip[4], u_char dest_mac[6], u_char interface_mac[6]) {
	struct iphdr *ip_hdr = (struct iphdr *) (p.payload + sizeof (struct ether_header));
	struct ether_header *eth_hdr = (struct ether_header *)(p.payload);

	memcpy(eth_hdr->ether_shost, interface_mac, 6);
	memcpy(eth_hdr->ether_dhost, dest_mac, 6);
	memcpy(&ip_hdr->daddr, dest_ip, 4);
	
	u_short old_checksum = ip_hdr->check;
	ip_hdr->check = 0;
	u_short new_checksum = ip_checksum(ip_hdr,sizeof(struct iphdr));
	ip_hdr->ttl--;
	if (old_checksum != new_checksum || ip_hdr->ttl < 1)
		return;
	ip_hdr->check = ip_checksum(ip_hdr,sizeof(struct iphdr));
	send_packet(p.interface, &p);
}
void IP (packet m, queue coada) {
	struct iphdr *ip_hdr = (struct iphdr *) (m.payload + sizeof (struct ether_header));
	int indice = CautareRtable(0, rtable_size, ip_hdr->daddr);

	if(indice >= 0) {
		m.interface = r_tabela[indice].interface;
		uint32_t next_hop = r_tabela[indice].next_hop;
		int arpI = CautareArptable(0, arp_table_len, next_hop);
		if(arpI == -1) {
			packet *m1 = (packet *)malloc(sizeof(packet));
			memcpy(m1, &m, sizeof(packet));
			queue_enq (coada, m1) ;

			packet p;
			p.len = 42;
			p.interface = r_tabela[indice].interface;
			struct ether_header *Hdr = (struct ether_header *)(p.payload);
			memcpy(Hdr->ether_dhost, BROADCAST_MAC, 6);
			get_interface_mac(p.interface, Hdr->ether_shost);
			Hdr->ether_type = htons(ETHERTYPE_ARP);

			struct ether_arp *eth_hdr = (struct ether_arp *)(p.payload + sizeof (struct ether_header));
			eth_hdr->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
			eth_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
			eth_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);
			eth_hdr->ea_hdr.ar_hln = 6;
			eth_hdr->ea_hdr.ar_pln = 4;
			uint32_t interfaceIP = inet_addr(get_interface_ip(p.interface));
			memcpy(eth_hdr->arp_spa, &interfaceIP, 4);
			memcpy(eth_hdr->arp_tpa, &r_tabela[indice].next_hop, 4);
			
			memcpy(eth_hdr->arp_tha, BROADCAST_MAC, 6);
			get_interface_mac(p.interface, eth_hdr->arp_sha);
			send_packet(p.interface, &p);
			return;
		}
		u_char destIP[4];
		u_char srcMac[6];
		get_interface_mac(m.interface, srcMac);
		memcpy(destIP, &ip_hdr->daddr, 4);
		transmitePachet(m, destIP, arp_tabela[arpI].mac, srcMac);
		return;
	}
}
void ARP(packet m, queue coada) {
	struct ether_arp *arp_h = (struct ether_arp *)(m.payload + sizeof (struct ether_header));
	unsigned short tip = ntohs(arp_h->ea_hdr.ar_op);
	u_char interface_mac[6];
	get_interface_mac(m.interface, interface_mac);

	if(tip == ARPOP_REQUEST) {
		arp_h->ea_hdr.ar_op = htons(ARPOP_REPLY);
		struct ether_header *eth_hdr = (struct ether_header *)(m.payload);
		uint8_t tmp[6];
		memcpy(tmp, eth_hdr->ether_shost, 6);
		memcpy(eth_hdr->ether_shost, interface_mac, 6);
		memcpy(eth_hdr->ether_dhost, tmp, 6);

		memcpy(tmp, arp_h->arp_spa, 4);
		memcpy(arp_h->arp_spa, arp_h->arp_tpa, 4);
		memcpy(arp_h->arp_tpa, tmp, 4);
		memcpy(arp_h->arp_tha, arp_h->arp_sha, 6);
		memcpy(arp_h->arp_sha, interface_mac, 6);
		send_packet(m.interface, &m);
		return;
	}
	uint32_t *sIP1 = (uint32_t *)arp_h->arp_spa;
	add_in_arp_table(*sIP1, arp_h->arp_sha);
	arp_h->ea_hdr.ar_op = htons(ARPOP_REQUEST);
	while(!queue_empty(coada)) {
		packet *p = queue_deq(coada);
		p->interface = m.interface;
		u_char srcMac[6];
		get_interface_mac(m.interface, srcMac);
		transmitePachet(*p, arp_h->arp_spa, arp_h->arp_sha, srcMac);
	}
}
int main(int argc, char *argv[]) {
	packet m; int rc; init();
	queue coada = queue_create();
	// tabela rtable statica
	struct route_table_entry rtable[65000];
	// tabela arptable statica
	struct arp_table arp_table[100];
	arp_tabela = arp_table;
	arp_table_max_len = 100;
	rtable_size = arp_table_len = 0;
	// elemente in tabelele rtable/arptable
	read_rtable(rtable);
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *Hdr = (struct ether_header *)(m.payload);
		if(ntohs(Hdr->ether_type) == ETHERTYPE_ARP) {
			ARP(m, coada); // Arp Header
		} else {
			IP(m, coada); // IP Header
		}
	}
	return 0;
}