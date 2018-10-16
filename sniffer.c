#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#define  PROMISCUOUS 1

struct   iphdr    *iph;
struct   tcphdr   *tcph;
struct   udphdr   *udph;
struct   icmp     *icmph;
static   pcap_t   *pd;
int sockfd;
int pflag;
int rflag;
int eflag;
int cflag;
int chcnt;
FILE* temp;
FILE* temp2;
// 기기 일련번호
char hp_idx[100];
//시간 관련
char       buf[80];
// 쓰레드 관련 변수
pthread_t timer_therad, signal_thread;
int tid, tid2, status;
pthread_mutex_t a_mutex = PTHREAD_MUTEX_INITIALIZER;
// 현재 경로 저장
char curDir[1000];

char *device, *filter_rule;

void packet_analysis(unsigned char *, const struct pcap_pkthdr *, 
                    const unsigned char *);

struct printer {
   pcap_handler f;
   int type;
};
   
/* datalink type에 따른 불리어질 함수들의 
   목록들을 갖는 구조체                       
 Data-link level type codes. 
#define DLT_NULL                0        no link-layer encapsulation 
#define DLT_EN10MB      		1        Ethernet (10Mb) 
#define DLT_EN3MB               2        Experimental Ethernet (3Mb)
#define DLT_AX25                3        Amateur Radio AX.25
#define DLT_PRONET      		4        Proteon ProNET Token Ring
#define DLT_CHAOS               5        Chaos
#define DLT_IEEE802    	 		6        IEEE 802 Networks
#define DLT_ARCNET      		7        ARCNET
#define DLT_SLIP                8        Serial Line IP
#define DLT_PPP         		9        Point-to-point Protocol
#define DLT_FDDI                10       FDDI
#define DLT_ATM_RFC1483 		11       LLC/SNAP encapsulated atm
#define DLT_RAW         		12       raw IP
#define DLT_SLIP_BSDOS  		13       BSD/OS Serial Line IP
#define DLT_PPP_BSDOS   		14       BSD/OS Point-to-point Protocol
bpf.h 라는 헤더화일에 위와 같은 내용으로 정의되어 있다.         */

static struct printer printers[] = {
   { packet_analysis, DLT_IEEE802 },
   { packet_analysis, DLT_EN10MB  },
   { NULL, 0 },
};
   
/*  datalink type에 따라 수행될 함수를 결정하게 된다.
    이는 pcap_handler라는 함수형 포인터의 값으로 대입된다. */
static pcap_handler lookup_printer(int type) 
{
	struct printer *p;

	for(p=printers; p->f; ++p)
		if(type == p->type)
			return p->f;
			
	perror("unknown data link type");
}

void *signal_func(void* data)
{
	time_t start, end;
	int i;
	start = time(0);

	i = 1;
	while(1)
	{
		end = time(0);
		if(end - start > 0.5)
		{
			temp2 = fopen("signal.txt", "a+");
			printf("===================================================================\n");
			char output[500];
			FILE *p = popen("iw dev wlan1 station dump | grep signal", "r");

			if(p != NULL) {
				i = 0;
				while(fgets(output, sizeof(output), p) != NULL)
				{
					fprintf(temp2, "%d : %d %s\n", i, end, output);
					printf("%d : ", i);
					printf("%d", end);
					printf("%s\n",output);
					i += 1;
				}
			}
			start = end;
			pclose(p);
			fclose(temp2);
			printf("===================================================================\n");
		}
	}
}

void *timer_func(void* data)
{
	time_t     now;
	struct tm  *tstruct;
	time_t start, end;
	char prefix[200] = "./s3_upload ";

	start = time(0);

	while(1)
	{
		end = time(0);
		if(end - start > 20)
		{
			printf("Timer Activated\n");
			pthread_mutex_lock(&a_mutex);
			fprintf(temp, "]");
			fclose(temp);

			strcat(prefix, buf);

			strcat(prefix, " ");
			strcat(prefix, hp_idx);

			printf("%s\n", prefix);
			system(prefix);

			now = time(0);
			tstruct = localtime(&now);
			strftime(buf, sizeof(buf), "%Y-%m-%d_%I-%M-%S-%p.json", tstruct); 
			temp = fopen(buf, "w");
			fprintf(temp, "[");
			pthread_mutex_unlock(&a_mutex);
			start = end;
			prefix[12] = '\0';
			printf("%s\n", prefix);
		}
		sleep(1);
	}

}

void createJSON(int protocolNum, int length, int srcPort, int dstPort, char* srcIP, char* dstIP, char* timestamp, char* dns)

{
	// JSON 
	pthread_mutex_lock(&a_mutex);
	fprintf(temp, "{\n");
	fprintf(temp, "  \"Index\": \"%s\",\n", hp_idx);
	fprintf(temp, "  \"Timestamp\": \"%s\",\n", timestamp);
	fprintf(temp, "  \"Protocol\": \"%d\",\n", protocolNum);
	fprintf(temp, "  \"Length\": \"%d\",\n", length);
	fprintf(temp, "  \"Source IP\": \"%s\",\n", srcIP);
	fprintf(temp, "  \"Destination IP\": \"%s\",\n", dstIP);
	fprintf(temp, "  \"Source Port\": \"%d\",\n", srcPort);
	fprintf(temp, "  \"Destination Port\": \"%d\",\n", dstPort);
	fprintf(temp, "  \"Payload\": \"%s\"\n", dns);
	fprintf(temp, "},\n");
	pthread_mutex_unlock(&a_mutex);
}


/* pcap_loop()에 의해 패킷을 잡을 때마다 불려지는 함수
   pcap_handler가 이 함수를 포인터하고 있기 때문이다 */
void packet_analysis(unsigned char *user, const struct pcap_pkthdr *h, 
                    const unsigned char *p)
{
	//int j, temp;
	unsigned int length = h->len;
	struct ether_header *ep;
	unsigned short ether_type;
	unsigned char *tcpdata, *udpdata,*icmpdata, temp_char;
	register unsigned int i;
	char       timestamp[80];
	time_t     now;
	struct tm  *tstruct;
	chcnt = 0;

	char srcIp[80];
	char destIp[80];
	char *temp;


	now = time(0);
	tstruct = localtime(&now);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tstruct); 

	if(rflag) {
		while(length--) {
			printf("%02x ", *(p++));
			if( (++chcnt % 16) == 0 ) printf("\n");
		}
		fprintf(stdout, "\n");
		return;
	}

	length -= sizeof(struct ether_header);
	
	// ethernet header mapping
	ep = (struct ether_header *)p;
	// ethernet header 14 bytes를 건너 뛴 포인터
	p += sizeof(struct ether_header);
	// datalink type
	ether_type = ntohs(ep->ether_type);
	
	//printf("\n");
	// Ethernet frame이 IEEE802인경우 ether_type필드가 길이필드가 된다.
	if(ether_type <= 1500) {
		;
		/*while(length--) {
			if(++is_llchdr <= 3) {
				fprintf(stdout,"%02x",*p++);
				continue;
			}
			if(++next_line == 16) {
				next_line = 0;      
				printf("\n");
			}
			printf("%02x",*p++);
		}*/
	}
	else 
	{    
		if(eflag) {
			/*
			printf("\n\n=================== Datalink layer ===================\n");
			for(j=0; j<ETH_ALEN; j++) {
				printf("%X", ep->ether_shost[j]);
						if(j != 5) printf(":");
			}       
			printf("  ------> ");
			for(j=0; j<ETH_ALEN; j++){ 
				printf("%X", ep->ether_dhost[j]); 
				if(j != 5) printf(":");
			}
			printf("\nether_type -> %x\n", ntohs(ep->ether_type));
			*/
		}

		iph = (struct iphdr *) p;
		i = 0;
		if (ntohs(ep->ether_type) == ETHERTYPE_IP) {        // ip 패킷인가?
			/*
			printf("\n\n===================    IP HEADER   ===================\n");
			printf("%s -----> ",   inet_ntoa(*(struct in_addr *)&iph->saddr));
			printf("%s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
			printf("Version:         %d\n", iph->version);
			printf("Herder Length:   %d\n", iph->ihl);
			printf("Service:         %#x\n",iph->tos);
			printf("Total Length:    %d\n", ntohs(iph->tot_len)); 
			printf("Identification : %d\n", ntohs(iph->id));
			printf("Fragment Offset: %d\n", ntohs(iph->frag_off)); 
			printf("Time to Live:    %d\n", iph->ttl);
			printf("Checksum:        %d\n", ntohs(iph->check));
			*/
			temp = inet_ntoa(*(struct in_addr *)&iph->saddr);
			strcpy(srcIp, temp);
			temp = inet_ntoa(*(struct in_addr *)&iph->daddr);
			strcpy(destIp, temp);
	
			if(iph->protocol == IPPROTO_TCP) {
				tcph = (struct tcphdr *) (p + iph->ihl * 4);
				// tcp data는 
				tcpdata = (unsigned char *) (p + (iph->ihl*4) + (tcph->doff * 4));
				createJSON(iph->protocol, ntohs(iph->tot_len), ntohs(tcph->source), ntohs(tcph->dest), srcIp, destIp, timestamp, "(None)");
				/*
				printf("\n\n===================   TCP HEADER   ===================\n");
				printf("Source Port:              %d\n", ntohs(tcph->source));
				printf("Destination Port:         %d\n", ntohs(tcph->dest));
				printf("Sequence Number:          %d\n", ntohl(tcph->seq));
				printf("Acknowledgement Number:   %d\n", ntohl(tcph->ack_seq));
				printf("Data Offset:              %d\n", tcph->doff);
				printf("Window:                   %d\n", ntohs(tcph->window));
				printf("URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n", 
				tcph->urg, tcph->ack, tcph->psh, tcph->rst, 
				tcph->syn, tcph->fin, ntohs(tcph->check), 
				ntohs(tcph->urg_ptr));
				printf("\n===================   TCP DATA(HEX)  =================\n"); 
				chcnt = 0;
				for(temp = (iph->ihl * 4) + (tcph->doff * 4); temp <= ntohs(iph->tot_len) - 1; temp++) {
					printf("%02x ", *(tcpdata++));
					if( (++chcnt % 16) == 0 ) printf("\n");
				}
				if (pflag) {
				   tcpdata = (unsigned char *) (p + (iph->ihl*4) + (tcph->doff * 4));
				   printf("\n===================   TCP DATA(CHAR)  =================\n"); 
				   for(temp = (iph->ihl * 4) + (tcph->doff * 4); temp <= ntohs(iph->tot_len) - 1; temp++) {
						temp_char = *tcpdata;
						if ( (temp_char == 0x0d) && ( *(tcpdata+1) == 0x0a ) ) {
							fprintf(stdout,"\n");
							tcpdata += 2;
							temp++;
							continue;
						}
						temp_char = ( ( temp_char >= ' ' ) && ( temp_char < 0x7f ) )? temp_char : '.';
						printf("%c", temp_char);
						tcpdata++;							
				   }
				}
				printf("\n>>>>> End of Data >>>>>\n");
				*/
			}
			else if(iph->protocol == IPPROTO_UDP) {
				udph = (struct udphdr *) (p + iph->ihl * 4);
				udpdata = (unsigned char *) (p + iph->ihl*4) + 8;
				createJSON(iph->protocol, ntohs(iph->tot_len), ntohs(udph->source), ntohs(udph->dest), srcIp, destIp, timestamp, "(None)");
				/*
				printf("\n==================== UDP HEADER =====================\n");
				printf("Source Port :      %d\n",ntohs(udph->source));
				printf("Destination Port : %d\n", ntohs(udph->dest));
				printf("Length :           %d\n", ntohs(udph->len));
				printf("Checksum :         %x\n", ntohs(udph->check));
						printf("\n===================  UDP DATA(HEX)  ================\n");   
				chcnt = 0;
				for(temp = (iph->ihl*4)+8; temp<=ntohs(iph->tot_len) -1; temp++) {
				   printf("%02x ", *(udpdata++));
				   if( (++chcnt % 16) == 0) printf("\n"); 
				}

				udpdata = (unsigned char *) (p + iph->ihl*4) + 8;
				if(pflag) {
					printf("\n===================  UDP DATA(CHAR)  ================\n");     
					for(temp = (iph->ihl*4)+8; temp<=ntohs(iph->tot_len) -1; temp++)  {
						temp_char = *udpdata;
						if ( (temp_char == 0x0d) && ( *(udpdata+1) == 0x0a ) ) {
							fprintf(stdout,"\n");
							udpdata += 2;
							temp++;
							continue;
						}
						temp_char = ( ( temp_char >= ' ' ) && ( temp_char < 0x7f ) )? temp_char : '.';
						printf("%c", temp_char);
						udpdata++;							
					}
				}
				
				printf("\n>>>>> End of Data >>>>>\n");
				*/
			}         
			else if(iph->protocol == IPPROTO_ICMP) {
				icmph = (struct icmp *) (p + iph->ihl * 4);
				icmpdata = (unsigned char *) (p + iph->ihl*4) + 8;
				createJSON(iph->protocol, ntohs(iph->tot_len), icmph->icmp_type, icmph->icmp_code, srcIp, destIp, timestamp, "(None)");
				/*
				printf("\n\n===================   ICMP HEADER   ===================\n");
				printf("Type :                    %d\n", icmph->icmp_type);
				printf("Code :                    %d\n", icmph->icmp_code);
				printf("Checksum :                %02x\n", icmph->icmp_cksum);
				printf("ID :                      %d\n", icmph->icmp_id);
				printf("Seq :                     %d\n", icmph->icmp_seq);
				printf("\n===================   ICMP DATA(HEX)  =================\n"); 
				chcnt = 0;
				for(temp = (iph->ihl * 4) + 8; temp <= ntohs(iph->tot_len) - 1; temp++) {
					printf("%02x ", *(icmpdata++));
					if( (++chcnt % 16) == 0 ) printf("\n");
				}
				printf("\n>>>>> End of Data >>>>>\n");
				*/
		   }
		}   
	}
}


void sig_int(int sig)
{
    pcap_close(pd);
    close(sockfd);
    fprintf(temp, "]");
    fclose(temp);
    pthread_kill(timer_therad, SIGQUIT);
    pthread_join(timer_therad, (void **)&status);
    pthread_join(signal_thread, (void **)&status);
    printf("Bye!!\n");
    exit(0);
}

void usage(void)
{
    fprintf(stdout," Usage : noh_pa filter_rule [-pch]\n");
    fprintf(stdout,"         -p  :  데이타를 문자로 출력한다.\n");
    fprintf(stdout,"         -c  :  주어진 숫자만큼의 패킷만 덤프한다\n");
    fprintf(stdout,"         -e  :  datalink layer를 출력한다.\n");
    fprintf(stdout,"         -r  :  잡은 패킷을 생으로 찍는다.\n");
    fprintf(stdout,"         -h  :  사용법\n");
}

int main(int argc, char *argv[])
{
	//struct  bpf_program fcode;
	pcap_handler printer;
	char    ebuf[PCAP_ERRBUF_SIZE];
	int     c, i, snaplen = 1514, /*size, */packetcnt;
	bpf_u_int32 /*myself, */localnet, netmask;
	unsigned char   *pcap_userdata;
	u_int index, /*res,*/ inum;
	pcap_if_t *alldevs, *d;
	// 시간 관련 변수
	time_t     now;
	struct tm  *tstruct;

	filter_rule = argv[1];          /* example : "src host xxx.xxx.xxx.xxx and tcp port 80" */
	
	signal(SIGINT,sig_int);
	getcwd(curDir, 1000);
    strcat(curDir, "/");
	
	// label 가져오기
    if(1 == access("hp_index.txt", F_OK))
    {
		printf("database request\n");
    }
    else
    {
		FILE *p = popen("iw dev wlan0 station dump | grep signal", "r");
		if(p != NULL) {
			while(fgets(hp_index, sizeof(hp_index), p) != NULL);
			printf("%s\n",hp_index);
		}
    }

	opterr = 0;
	
	if(argc < 1) {
		usage(); 
		exit(1);
	}
	
	while( (c = getopt(argc, argv,"c:pher")) != -1) {
		switch(c) {
			case 'p' :
				pflag = 1; 
				break;
			case 'c' :
				cflag = 1; 
				packetcnt = atoi(optarg);
				if(packetcnt <= 0) {
					fprintf(stderr,"invalid number %s",optarg);
					exit(1);
				}
				break;
			case 'e' :
				eflag = 1;
				break;          
			case 'r' :
				rflag = 1;
				break;          
			case 'h' :
				usage();
				exit(1);
		}
	}           
	
	if (pcap_findalldevs(&alldevs, ebuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", ebuf);
		return -1;
	}

	index = 0;
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++index, d->name);

		if (d->description)
		{
			printf(" (%s)\n", d->description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}
	
	if (index == 0)
	{
		fprintf(stderr, "No interfaces found! Exiting.\n");
		return -1;
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &inum);


	for (d = alldevs, index = 0; index < inum - 1; d = d->next, index++);

   	pd = pcap_open_live(d->name, snaplen, PROMISCUOUS, 1000, ebuf);
	if(pd == NULL) {
		perror(ebuf);          
		exit(-1);
	}

	fprintf(stdout, "device = %s\n", d->name);

	i = pcap_snapshot(pd);
	if(snaplen < i) {
		perror(ebuf);                            
		exit(-1);
	}
	
	if(pcap_lookupnet(d->name, &localnet, &netmask, ebuf) < 0) {
		perror(ebuf);
		exit(-1);
	}
	
	setuid(getuid());
	
	fflush(stderr);
	
	printer = lookup_printer(pcap_datalink(pd));
	pcap_userdata = 0;

	now = time(0);
	tstruct = localtime(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d_%I-%M-%S-%p.json", tstruct); 

	temp = fopen(buf, "w");
	fprintf(temp, "[");

	tid = pthread_create(&timer_therad, NULL, timer_func, NULL);
	tid2 = pthread_create(&signal_thread, NULL, signal_func, NULL);
    if (tid < 0)
    {
        perror("thread create error : ");
        exit(0);
    }
    if (tid2 < 0)
    {
        perror("thread create error : ");
        exit(0);
    }

	if(pcap_loop(pd, packetcnt, printer, pcap_userdata) < 0) {
		perror("pcap_loop error");
		exit(-1);
	}
	
	pthread_join(timer_therad, (void **)&status);
	pthread_join(signal_thread, (void **)&status);
	pcap_close(pd);
	exit(0);
}
	
