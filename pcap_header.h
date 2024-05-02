#include <stdbool.h>
#include <pcap.h>
#ifndef	H_PCAP_HDR
#define	H_PCAP_HDR

static int counter = 0;
static struct option long_opt[] = {
                {"verbose",             no_argument,            0,  1},
                {"interface",           required_argument,      0, 'i'},
                {"protocol",            required_argument,      0, 'p'},
                {"source-port",         required_argument,      0, 's'},
                {"destination-port",    required_argument,      0, 'd'},
                {"source-ip",           required_argument,      0, 'S'},
                {"destination-ip",      required_argument,      0, 'D'},
                {"port-range",          required_argument,      0, 'r'},
                {"list-interfaces",     no_argument,            0, 'l'},
                {"nb-packet",           required_argument,      0, 'n'},
                {"help",                no_argument,            0, 'h'},
                {0,0,0,0}
};

void	hexdump(const char *buffer, int length);
void	list_all_interfaces(void);
int     apply_bpf_program(struct bpf_program *bpf, char filters[][30], bool *is_set, pcap_t *handle);
void    packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);


#endif
