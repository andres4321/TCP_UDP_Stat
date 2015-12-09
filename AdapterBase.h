#pragma once


#define CLEAR_ERROR_STATE 0
#define NO_ERRORS 0
#define ERRORS 1
#define FAILED 2

#define STATISTICS_MAP_1 1
#define STATISTICS_MAP_2 2
#define TCP 6
#define UDP 17
#define IPTOSBUFFERS    12

class AdapterBase
{
private:
	void *g_alldevs;

	virtual void IncreaseCounter(char* remote_address, int protocol, int ErrorCode) { return; };
	virtual void AddLocalAddress( unsigned int LocalAddress ) { return; };
	virtual void SetAdapterName(char* pc_AdapterName) { return; };
	virtual unsigned int DetectRemoteAddress(unsigned int daddr, unsigned int saddr) { return daddr; };
protected:
	int AdapterStatistics(char* AdapterName);
public:
	int choose_ether_adapter_via_console();
	void clean_up_pcap1();
};
