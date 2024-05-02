#include <libgen.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include "print_colors.h"
#include <errno.h>
#include <string.h>
#include "pcap_header.h"

int	main(int argc, char **argv)
{
	struct	pcap_pkthdr	header;
	struct	bpf_program	filt[6];
	const unsigned char	*packet;
	char			errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t		*alldevs, *dev;
	char			interface[50];
	pcap_t			*pcap_handle;
	int			i, c, nb_pkt, option_index = 0;
	char			filters[6][30] = {"", "src port ", "dst port ", "src ", "dst ", "portrange "};
	bool			is_set[6] = {0, 0, 0, 0, 0, 0};
	bool			verbose = 0;

	if (argc < 2 || !strncmp(argv[1], "--help", 7))
	{
		printf_colored(YELLOW, "\n%s [-vipln [filters: s|d|S|D|r]]\n", basename(argv[0]));
		printf_colored(YELLOW, "  -v:"); printf(" verbose mode\n");
		printf_colored(YELLOW, "  -i <interface>:"); printf(" interface on which to sniff\n");
		printf_colored(YELLOW, "  -p <protocol>:"); printf(" protocol to sniff\n");
		printf_colored(YELLOW, "  -s <source port>: "); printf("source port to filter (e.g: -sP 80)\n");
		printf_colored(YELLOW, "  -d <dest. port>: "); printf("destination port to filter\n");
		printf_colored(YELLOW, "  -S <source IP>: "); printf("source IP to filter\n");
		printf_colored(YELLOW, "  -D <dest. IP>: "); printf("destination IP to filter");
		printf_colored(YELLOW, "  -r <port range>: "); printf("port range (e.g: -pR 10-500)\n");
		printf_colored(YELLOW, "  -l:"); printf(" list all network interfaces\n");
		printf_colored(YELLOW, "  -n <# of packets>:"); printf(" number of packet to sniff (10 by default)\n");
		printf_colored(YELLOW, "  --help:"); printf(" displays this menu\n");
		return (-1);
	}

	while ((c = getopt_long(argc, argv, "v:i:p:s:d:S:D:r:n:lh", long_opt, &option_index)) != -1) {
		switch (c) {
			case 'v':
				verbose = 1;
				break;
			case 'i':
				strncpy(interface, optarg, 50);
				break;
			case 'p':
				is_set[0] = 1;
				strncpy(filters[0], optarg, sizeof(filters[0])-1);
				break;
			case 's':
				is_set[1] = 1;
				strncat(filters[1], optarg, sizeof(filters[1])-1);
				break;
			case 'd':
				is_set[2] = 1;
				strncat(filters[2], optarg, sizeof(filters[2])-1);
				break;
			case 'S':
				is_set[3] = 1;
				strncat(filters[3], optarg, sizeof(filters[3])-1);
				break;
			case 'D':
				is_set[4] = 1;
				strncat(filters[4], optarg, sizeof(filters[4])-1);
				break;
			case 'r':
				is_set[5] = 1;
				strncat(filters[5], optarg, sizeof(filters[5])-1);
				break;
			case 'l':
				list_all_interfaces();
				exit(0);
			case 'n':
				nb_pkt = atoi(optarg);
				if (nb_pkt <= 0)
					nb_pkt = 10;
				break;
			case '?':
				if (optopt == 'i' || optopt == 'p' || optopt == 'n'
					|| optopt == 'd' || optopt == 'D' || optopt == 's'
					|| optopt == 'S' || optopt == 'r')
					printf_colored(RED, "Option -%c requires an argument\n", optopt);
				else if (isprint(optopt))
					printf_colored(RED, "Unknown option '-%c'\n", optopt);
				else
					printf_colored(RED, "Unknown option character\n");
				return (-1);
			default:
				abort();
		}

		for (int index = optind; index < argc; index++)
		{
			printf_colored(RED, "Non option argument\n");
		}
	}

	if (nb_pkt <= 0) {
		printf_colored(RED, "Number of packets to sniff must be greater than 0\n");
		exit(1);
	}

	if (-1 == (pcap_findalldevs(&alldevs, errbuf))) {
		printf_colored(RED, "main::pcap_findalldevs(): %s\n", errbuf);
		exit(1);
	}

	printf("%s\n", interface);
	for (dev = alldevs; strncmp(dev->name, interface, 50); dev = dev->next)
	{
		if (strncmp(dev->name, interface, 50) && dev->next == NULL) {
			printf_colored(RED, "No such interface\n");
			pcap_freealldevs(alldevs);
			exit(1);
		}
	}

	printf_colored(YELLOW, "Sniffing on device %s:\n", dev->name);
	if (NULL == (pcap_handle = pcap_open_live(dev->name, 4096, 1, 1000, errbuf))) {
		fprintf(stderr, "main::pcap_open_live(): %s\n", errbuf);
		pcap_freealldevs(alldevs);
		exit(1);
	}

	if (-1 == (apply_bpf_program(filt, filters, is_set, pcap_handle))) {
		printf_colored(RED, "main::apply_bpf_program(): %s\n", pcap_geterr(pcap_handle));
		pcap_freealldevs(alldevs);
		exit(1);
	}

	if (-1 == (pcap_loop(pcap_handle, nb_pkt, packet_handler, NULL))) {
		printf_colored(RED, "main::pcap_loop(): %s\n", pcap_geterr(pcap_handle));
		pcap_freealldevs(alldevs);
		exit(1);
	}

	pcap_freealldevs(alldevs);

	return (0);
}
