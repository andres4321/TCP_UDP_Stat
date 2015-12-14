#pragma once

#define CLEAR_ERROR_STATE 0
#define NO_ERRORS 0
#define ERRORS 1

#define TCP 6
#define UDP 17

class AdapterBase
{
private:
	virtual void IncreaseCounter(char* remote_address, int protocol, int ErrorCode) { return; };
	virtual void AddLocalAddress( unsigned int LocalAddress ) { return; };
	virtual void SetAdapterName(char* pc_AdapterName) { return; };
	virtual unsigned int DetectRemoteAddress(unsigned int daddr, unsigned int saddr) { return daddr; };
	virtual void Test_Adapter_Sleep(int duration) { return; };
protected:
	void *g_alldevs = 0;
	int AdapterStatistics(char* AdapterName);
	void clean_up_pcap1();
public:
	char* iptos(unsigned long int ui_Address);
	char ch_iptos_buffer[20];
	int choose_ether_adapter_via_console();
};
