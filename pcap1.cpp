#define HAVE_REMOTE
#include "pcap.h"
#include "pcap1.h"

pcap_if_t *alldevs;
pcap_if_t *d;

int get_adapter_name(char** cAdapterName)
{
	pcap_addr_t *a;
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
		printf("Enter choice (0..%d): ", i-1);
		scanf("%d", &iUserChoice);
	} while (iUserChoice > i || iUserChoice < 0);

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< iUserChoice; d = d->next, i++);

	*cAdapterName = d->name;

	return 0;
}

void clean_up_pcap1()
{
	pcap_freealldevs(alldevs);
}

pcap_addr_t *a;

int get_first_non_local_IP_address(char* pc_AdapterName, unsigned int* ui_Address, char* pc_Address, unsigned int* ui_netmask)
{
	char *iptos(u_long in);

	for (d = alldevs; d != NULL; d = d->next)
	{
		//printf("%d. %s", ++i, d->name);
		if ( strcmp(pc_AdapterName, d->name) ) continue;

		for (a = d->addresses; a; a = a->next)
		{
			//printf("\tAddress Family: #%d\n", a->addr->sa_family);
			if (a->addr->sa_family != AF_INET) continue;
			if (a->addr)
			{
				sprintf( pc_Address, "%s", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
				*ui_Address = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
				*ui_netmask = ((struct sockaddr_in *)(a->netmask))->sin_addr.S_un.S_addr;
				return 0;
			}
			else continue;
		}
	}
	return -1;
}

int get_next_non_local_IP_address(unsigned int* ui_Address, char* pc_Address, unsigned int* ui_netmask)
{
	char *iptos(u_long in);

	for (a = a->next; a; a = a->next)
	{
		//printf("\tAddress Family: #%d\n", a->addr->sa_family);
		if (a->addr->sa_family != AF_INET) continue;
		if (a->addr)
		{
			sprintf(pc_Address, "%s", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			*ui_Address = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
			*ui_netmask = ((struct sockaddr_in *)(a->netmask))->sin_addr.S_un.S_addr;
			return 1;
		}
		else continue;
	}

	return 0;
}

void AdapterStatistics(char* AdapterName, char* StatisticsFilter, unsigned int* StatisticsCounter, unsigned int ui_netmask, int* ErrCode )
{
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct tm ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;

	pcap_t *adhandle;

	struct bpf_program fcode;

	int iUserChoice, res;

	/* Open the device */
	//printf("Opening %s\n", StatisticsFilter);
	if ((adhandle = pcap_open(AdapterName, //d->name,          // name of the device
		65536,            // portion of the packet to capture. 
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_MAX_RESPONSIVENESS,    // NO promiscuous mode
		0,//1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		*ErrCode = 1;
		printf("Exiting opening:  %s\n", StatisticsFilter);
		return;
	}

	/* Check the link layer. We support only Ethernet AS DEFINED. */
	//if (pcap_datalink(adhandle) != DLT_EN10MB)
	//{
	//	fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
	//	/* Free the device list */
	//	pcap_freealldevs(alldevs);
	//	return -1;
	//}
	//printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
//	pcap_freealldevs(alldevs);

	//printf("Going to compile %s\n", StatisticsFilter);
	res = pcap_compile(adhandle, &fcode, StatisticsFilter, 1, ui_netmask);
	//printf("Compiled res = %d %s\n", res, StatisticsFilter);
	if ( res < 0)
	{
		//fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		///* Free the device list */
		//pcap_freealldevs(alldevs);
		*ErrCode = ERRORS;
		printf("Exiting compilefilter: res = %d %s\n", res, StatisticsFilter);
		return;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		//fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		*ErrCode = ERRORS;
		printf("Exiting setfilter:  %s\n", StatisticsFilter);
		return;
	}

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
			*ErrCode = 1;
		}
		else if (res == 1)
			(*StatisticsCounter)++;

	}

}

int old_main()
{
	pcap_if_t *d;
	pcap_addr_t *a;
	char *iptos(u_long in);

	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct tm ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;

	pcap_t *adhandle;

	int iUserChoice, res;

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs_ex (PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

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

		printf(")\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return 0;
	}

	do
	{
		printf ( "Enter choice: ");
		scanf ( "%d", &iUserChoice );
	} while (iUserChoice > i || iUserChoice < 0);

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< iUserChoice; d = d->next, i++);


	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture. 
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_MAX_RESPONSIVENESS,    // NO promiscuous mode
		0,//1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet AS DEFINED. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* Retrieve the packets */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* Timeout elapsed */
			continue;

		/* convert the timestamp to readable format */
		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	}

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}


	return 0;
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
