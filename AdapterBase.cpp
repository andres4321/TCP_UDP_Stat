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

//pcap_if_t *g_alldevs;

int AdapterBase::choose_ether_adapter_via_console()
{
	pcap_if_t *d;
	pcap_addr_t *a;
	pcap_if_t *alldevs;
	char *iptos(u_long in);

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
		return 2;
	}

	do
	{
		printf("Enter choice (0..%d): ", i - 1);
		scanf("%d", &iUserChoice);
	} while (iUserChoice > i || iUserChoice < 0);

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< iUserChoice; d = d->next, i++);

	//*cAdapterName = d->name;
	SetAdapterName(d->name);

	for (a = d->addresses; a; a = a->next)
	{
		if (a->addr->sa_family != AF_INET) continue;
		if (a->addr) AddLocalAddress( (unsigned int) (((struct sockaddr_in *)a->addr)->sin_addr.s_addr) );
	}


	return 0;
}

void AdapterBase::clean_up_pcap1()
{
	pcap_freealldevs( (pcap_if_t*)g_alldevs);
}


int AdapterBase::AdapterStatistics( char* AdapterName )
{
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *iptos(u_long in);

	struct tm ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;

	pcap_t *adhandle;
	ip_header *ih;

	struct bpf_program fcode;

	int iUserChoice, res;

	unsigned int RemoteAddress;

	/* Open the device */
	//printf("Opening %s\n", StatisticsFilter);
	if ((adhandle = pcap_open(AdapterName, //d->name,          // name of the device
		34, //65536,            // portion of the packet to capture. 
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_MAX_RESPONSIVENESS,    // NO promiscuous mode
		0,//1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		//*ErrCode = 1;
		pcap_freealldevs( (pcap_if_t*) g_alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet AS DEFINED. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		//fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs( (pcap_if_t*)g_alldevs);
		return -2;
	}
	//printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	//	pcap_freealldevs(alldevs);

	//printf("Going to compile %s\n", StatisticsFilter);

	/* Retrieve the packets */
	while (1) {

		res = pcap_next_ex(adhandle, &header, &pkt_data);
		//		printf("res = %d\n", res);
		//		if (res == 0)
		/* Timeout elapsed */
		//			continue;

		/* convert the timestamp to readable format */
		//local_tv_sec = header->ts.tv_sec;
		//localtime_s(&ltime, &local_tv_sec);
		//strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

		//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

		if (res == -1) {
			//		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
			//		return -1;
			//*ErrCode = 1;
			IncreaseCounter("Errors:", TCP, ERRORS);
		}
		else if (res == 1)
		{
			//(*StatisticsCounter)++;
			/* retireve the position of the ip header */
			ih = (ip_header *)(pkt_data + 14); //length of ethernet header

			if (ih->proto != TCP && ih->proto != UDP) continue;

			RemoteAddress = DetectRemoteAddress(ih->daddr, ih->saddr);

			IncreaseCounter(iptos(RemoteAddress), ih->proto, NO_ERRORS);
		}

	}

}


/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
