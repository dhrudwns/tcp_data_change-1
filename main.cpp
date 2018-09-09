
#include <stdio.h>
#include <stdlib.h>					//strncmp
#include <string>					//std::string
#include <string.h>
#include <iostream>
#include <unordered_set>
#include <set>
#include <fstream>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <libnet/libnet-macros.h>
#define LIBNET_LIL_ENDIAN 1
#include <libnet/libnet-headers.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
using namespace std;

uint16_t flag = 0;
uint32_t new_data_len;
unsigned char* new_data;

#pragma pack(push,1)
struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};
#pragma pack(pop)
#define CARRY 65536

uint16_t calculate(uint16_t* data, int dataLen)
{
    uint16_t result;
    int tempChecksum=0;
    int length;
    bool flag=false;
    if((dataLen%2)==0)
        length=dataLen/2;
    else
    {
        length=(dataLen/2)+1;
        flag=true;
    }

    for (int i = 0; i < length; ++i) // cal 2byte unit
    {
        if(i==length-1&&flag) //last num is odd num
            tempChecksum+=ntohs(data[i]&0x00ff);
        else
            tempChecksum+=ntohs(data[i]);

        if(tempChecksum>CARRY)
                tempChecksum=(tempChecksum-CARRY)+1;
    }

    result=tempChecksum;
    return result;
}

uint16_t calTCPChecksum(uint8_t *data,int dataLen)
{
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //saved by network byte order

    //init Pseudoheader
    struct libnet_ipv4_hdr *iph=(struct libnet_ipv4_hdr*)data;
    struct libnet_tcp_hdr *tcph=(struct libnet_tcp_hdr*)(data+iph->ip_hl*4);

    memcpy(&pseudoheader.srcIP,&iph->ip_src,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->ip_dst,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->ip_p;
    pseudoheader.TCPLen=htons(dataLen-(iph->ip_hl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->th_sum=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));

    uint16_t checksum;
    int tempCheck;

    if((tempCheck=pseudoResult+tcpHeaderResult)>CARRY)
        checksum=(tempCheck-CARRY) +1;
    else
        checksum=tempCheck;


    checksum=ntohs(checksum^0xffff); //xor checksum
    tcph->th_sum=checksum;

    return checksum;
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
    	if (ph) {
        	id = ntohl(ph->packet_id);
    	}

	ret = nfq_get_payload(tb, &data);
	if(ret >= 0) {
		new_data = data;
		struct libnet_ipv4_hdr* ipH = (struct libnet_ipv4_hdr *) data;
		if(ipH->ip_p == 6){
			data += (ipH->ip_hl)*4;
			struct libnet_tcp_hdr* tcpH = (struct libnet_tcp_hdr *) data;
			u_int16_t len = (ipH->ip_hl * 4)+(tcpH->th_off * 4);

			if(ntohs(tcpH->th_sport) == 80 && (ipH->ip_len > len)){
				data += (tcpH->th_off * 4);
				string s_data;
				s_data = (char *) data;

				if(s_data.find("hacking") != string::npos){
					size_t pos = 0;
					while((pos = s_data.find("hacking", pos)) != string::npos){
						s_data.replace(pos, 7, "HOOKING");
						pos += 7;
					}
					memcpy((new_data + len), s_data.c_str(), (ret - len));
					calTCPChecksum(new_data ,ret);
//					cout << "------------------------------------------------------------" << ret << endl;
//					cout << (data + len) << endl;
//					for(int i=0; i<ret; i++){
//						if(i % 8 == 0) cout << "   ";
//						if(i % 16 == 0) cout << endl;
//						printf("%02x ", new_data[i+2]);
//					}
					new_data_len = ret;
					flag = 1;
				}
				else flag = 0;
			}

		}
	}

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);

    if(flag == 0)
    	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else
	return nfq_set_verdict(qh, id, NF_ACCEPT, new_data_len, new_data);

}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        printf("error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        printf("error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        printf("error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");

    qh = nfq_create_queue(h,  0, &cb, NULL);					// Queue create
    if (!qh) {
        printf("error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
 //           printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
