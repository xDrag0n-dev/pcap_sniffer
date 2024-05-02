#include <stdio.h>
#include "print_colors.h"
#include <getopt.h>
#include "pcap_header.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <netinet/if_ether.h>
#include <pcap.h>

void    hexdump(const char *buffer, int length)
{
        int     i;

        if (length <= 0)
                return;
        printf("\n\t");
        for (i = 0; i < length; i++) {
                if (i != 0 && i % 16 == 0)
                        printf("\n\t");
                printf("%02X ", buffer[i] & 0xFF);
        }
        printf("\n\n\t");
        for (i = 0; i < length; i++) {
                if (i != 0 && i % 48 == 0)
                        printf("\n\t");
                printf("%1c", (buffer[i] > 31 && buffer[i] < 127) ? buffer[i] : '.');
        }
        printf("\n\n");
}

void    list_all_interfaces(void)
{
        pcap_if_t       *alldevs, *dev;
        char            errbuf[PCAP_ERRBUF_SIZE];

        if (-1 == (pcap_findalldevs(&alldevs, errbuf))) {
                printf_colored(RED, "list_all_interfaces::pcap_findalldevs(): ");
                printf_colored(RED, "failed to list network interfaces\n");
                return ;
        }

        for (dev = alldevs; dev != NULL; dev = dev->next) {
                printf("\t%s", dev->name);
                if (dev->description != NULL)
                        printf(" -> %s\n", dev->description);
                else
                        putchar('\n');
        }

        pcap_freealldevs(alldevs);
}

int     apply_bpf_program(struct bpf_program *bpf, char filters[][30], bool *is_set, pcap_t *handle)
{
        /* Compile and apply set filters here, then call the function in the main(): */
        int     i;

        if (filters == NULL || !is_set || !handle)
                return (-1);

        i = 0;
        while (i < 6) {
                if (is_set[i])
                        if (-1 == (pcap_compile(handle, &bpf[i], filters[i], 0, PCAP_NETMASK_UNKNOWN)))
                                return (-1);
                i++;
        }
        i = 0;
        while (i < 6) {
                if (is_set[i])
                        if (-1 == (pcap_setfilter(handle, &bpf[i])))
                                return (-1);
                i++;
        }

        return (0);
}

void    packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
        /* Do something for each packet in the loop here */
        const struct    ether_header    *eth;
        const struct    ip              *ip;
        const struct    tcphdr          *tcp;

        eth = (const struct ether_header *)packet;
        ip = (const struct ip *)(packet + sizeof(struct ether_header));
        tcp = (const struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

        char    src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        char    src_port[6], dst_port[6];

        inet_ntop(AF_INET, &ip->ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip->ip_dst, dst_ip, sizeof(dst_ip));

        snprintf(src_port, sizeof(src_port), "%d", ntohs(tcp->th_sport));
        snprintf(dst_port, sizeof(dst_port), "%d", ntohs(tcp->th_dport));

        printf_colored(YELLOW, "Got a %d/%d bytes packet (#%d):\n\n", header->len, header->caplen, counter++);
        printf_colored(BLUE, "\tSource IP Address: %s -> Source Port: %s\n", src_ip, src_port);
        printf_colored(BLUE, "\tDest.  IP Address: %s -> Dest.  Port: %s\n", dst_ip, dst_port);
        printf_colored(BLUE, "\tSequence Number: %u\n", ntohs(tcp->th_seq));
        printf_colored(BLUE, "\tACK Number: %u\n", ntohs(tcp->th_ack));
        printf_colored(BLUE, "\tHeader Length: %u bytes\n", (unsigned int)tcp->th_off * 4);
        printf_colored(BLUE, "\tFlags: %s%s%s%s%s%s\n",
                        (tcp->th_flags & TH_SYN)  ? "SYN " : "",
                        (tcp->th_flags & TH_ACK)  ? "ACK " : "",
                        (tcp->th_flags & TH_RST)  ? "RST " : "",
                        (tcp->th_flags & TH_FIN)  ? "FIN " : "",
                        (tcp->th_flags & TH_PUSH) ? "PSH " : "",
                        (tcp->th_flags & TH_URG)  ? "URG " : "");
        printf_colored(BLUE, "\tWindow Size: %u\n", ntohs(tcp->th_win));
        printf_colored(BLUE, "\tChecksum: %u\n", ntohs(tcp->th_sum));
        printf_colored(BLUE, "\tUrgent Pointer: %u\n\n", ntohs(tcp->th_urp));
        printf_colored(BLUE, "\tPACKET HEXDUMP:");
        hexdump(packet, header->caplen);
}
