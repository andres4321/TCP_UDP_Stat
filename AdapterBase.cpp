#define HAVE_REMOTE
#include "pcap.h"
#include "AdapterBase.h"

/* 4 bytes IP address */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	/*ip_address*/  u_long saddr;      // Source address
	/*ip_address*/  u_long daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;


int AdapterBase::choose_ether_adapter_via_console()
{
	pcap_if_t *d;
	pcap_addr_t *a;
	pcap_if_t *alldevs;

	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	int iUserChoice;

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return 1;
	}

	g_alldevs = (void *)alldevs;

	/* Print the list */
	for (d = alldevs; d != NULL; d = d->next)
	{
		//printf("%d. %s", ++i, d->name);
		if (d->description)
			printf("%2d - %s\n        ( ", i++, d->description);
		else
			printf("%2d - (%s)\n        ( ", i++, d->name);

		for (a = d->addresses; a; a = a->next)
		{
			//printf("\tAddress Family: #%d\n", a->addr->sa_family);
			if (a->addr->sa_family != AF_INET) continue;
			if (a->addr) printf("%s ", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
		}

		printf(")\n\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		clean_up_pcap1();
		return 2;
	}

	do
	{
		printf("Enter choice (0..%d): ", i - 1);
		scanf("%d", &iUserChoice);
	} while (iUserChoice > i || iUserChoice < 0);

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< iUserChoice; d = d->next, i++);

	SetAdapterName(d->name);

	for (a = d->addresses; a; a = a->next)
	{
		if (a->addr->sa_family != AF_INET) continue;
		if (a->addr) AddLocalAddress( (unsigned int) (((struct sockaddr_in *)a->addr)->sin_addr.s_addr) );
	}

	clean_up_pcap1();

	return 0;
}

void AdapterBase::clean_up_pcap1()
{
	pcap_freealldevs( (pcap_if_t*)g_alldevs);
	g_alldevs = 0;
}

#ifndef GOOGLE_TEST
int AdapterBase::AdapterStatistics( char* AdapterName )
{
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	pcap_t *adhandle;
	ip_header *ih;

	int res;

	unsigned int RemoteAddress;

	/* Open the device */
	if ((adhandle = pcap_open(AdapterName, // name of the device
		34, // portion of the packet to capture, 34 enogh to capture addresses
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_MAX_RESPONSIVENESS,    // NO promiscuous mode
		0,//1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		return -1;
	}

	/* Check the link layer. We support only Ethernet AS DEFINED. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		return -3;
	}

	/* Retrieve the packets */
	while (1) {

		res = pcap_next_ex(adhandle, &header, &pkt_data);

		if (res == -1) {
			IncreaseCounter("Errors:", TCP, ERRORS);
		}
		else if (res == 1)
		{
			/* retireve the position of the ip header */
			ih = (ip_header *)(pkt_data + 14); //length of ethernet header

			if (ih->proto != TCP && ih->proto != UDP) continue;

			RemoteAddress = DetectRemoteAddress(ih->daddr, ih->saddr);

			IncreaseCounter(iptos(RemoteAddress), ih->proto, NO_ERRORS);
		}

	}

}
#else
// VERSION FOR TEST!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
int AdapterBase::AdapterStatistics(char* AdapterName)
{
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	pcap_t *adhandle;
	ip_header *ih;

	int res;

	unsigned int RemoteAddress;

	char source[PCAP_BUF_SIZE];

	if (pcap_createsrcstr(source,         // variable that will keep the source string
		PCAP_SRC_FILE,  // we want to open a file
		NULL,           // remote host
		NULL,           // port on the remote host
		"TestFile.pcap",        // name of the file we want to open
		errbuf          // error buffer
		) != 0)
	{
		return -1;
	}

	/* Open the device */

	if ((adhandle = pcap_open(source, // name of the device
		34, // portion of the packet to capture, 34 enough to capture addresses
		PCAP_OPENFLAG_MAX_RESPONSIVENESS,    // NO promiscuous mode
		0,//1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		return -1;
	}

	/* Retrieve the packets */
	for (i = 0;; i++) {

		if (i == 0) Test_Adapter_Sleep(500);
		if ( i && i % 10000 == 0 ) Test_Adapter_Sleep(5000);

		res = pcap_next_ex(adhandle, &header, &pkt_data);

		if (res == -1) {
			IncreaseCounter("Errors:", TCP, ERRORS);
		}
		else if (res == 1)
		{
			ih = (ip_header *)(pkt_data + 14); //length of ethernet header

			if (ih->proto != TCP && ih->proto != UDP) continue;

			RemoteAddress = DetectRemoteAddress(ih->daddr, ih->saddr);

			IncreaseCounter(iptos(RemoteAddress), ih->proto, NO_ERRORS);
		}
		else if (res == -2)
		{
			return -2; // EOF reached
		}

	}
}
#endif
char* AdapterBase::iptos(unsigned long int in)
{
	u_char *p;

	p = (u_char *)&in;
	_snprintf_s(ch_iptos_buffer, 20, 19, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return ch_iptos_buffer;
}
