#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define u_char unsigned char
#define u_short unsigned short

typedef struct dns_head{
	u_short transaction_id;
	u_short flag;
	u_short query_count;
	u_short answer_count;
	u_short auth_count;
	u_short addition_count;
}DNS_HEADER;

typedef struct dns_query{
	u_char *name;
	u_short type;
	u_short class;
}DNS_QUERY;


void sendDnsRequest(char *domain,char* target_ip,int sock){
	//init dns header
	DNS_HEADER dns_hd;
	dns_hd.transaction_id = rand()%65536;
	memcpy(&(dns_hd.flag),(u_char *)"\x01\x00",2);
	dns_hd.query_count = htons(1);
	dns_hd.answer_count = htons(0);
	dns_hd.auth_count = htons(0);
	dns_hd.addition_count = htons(0);
	//init dns query
	char *query = (char *)malloc(strlen(domain)+2);
	memset( query, 0,strlen(domain)+1);
	const char *split = ".";
	char *tmp = (char *)malloc(strlen(domain));
	memcpy( tmp, domain,strlen(domain));
	char *substr = strtok(tmp,split);
	int query_name_size = 0;
	while(substr != NULL){
		memset(query+query_name_size,strlen(substr),1);
		query_name_size++;
		memcpy(query+query_name_size,substr,strlen(substr));
		query_name_size += strlen(substr);
		substr = strtok( NULL, "." );
	}
	query_name_size++;
	DNS_QUERY dns_qr;
	dns_qr.name = query;
	dns_qr.type = htons(1);
	dns_qr.class = htons(1);
	printf("%s\n",dns_qr.name);
	//udp
	struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = inet_addr(target_ip);
    int header_size = sizeof(dns_hd);
    int query_remain_size = sizeof(dns_qr)-sizeof(dns_qr.name);
    int dns_packet_size = header_size+query_name_size+query_remain_size;
    char *buff = malloc(dns_packet_size);
    memset(buff,0,dns_packet_size);
    memcpy(buff,&dns_hd,header_size);
    memcpy(buff+header_size,dns_qr.name,query_name_size);
    memcpy(buff+header_size+query_name_size,&(dns_qr.type),query_remain_size);
    printf("dns packet size:%i\n",dns_packet_size);
    if(sendto(sock, buff, dns_packet_size, 0, (struct sockaddr *)&addr, sizeof(addr))<=0){
    	perror("send dns error");
	    exit(1);
    }
	//free
	free(buff);
	free(query);
	free(tmp);
}

void receiveDnsAnswer(int socket){
	const int BUFFSIZE = 65515;//udp max size = 65535-20
	u_char *dns_rp = malloc(BUFFSIZE);
	memset(dns_rp,0,BUFFSIZE);
	while(1){
		int n = recvfrom(socket, dns_rp, BUFFSIZE, 0, NULL, 0);
		if(n <= 0){
			perror("receive arp error");
			exit(1);
		}else{
			printf("received packet size:%i\n",n);
		}
	}
	free(dns_rp);
}

void main(int argc,char **argv){
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	// sendDnsRequest("www.laitouba.com","192.168.199.1",sock);
	struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	int n = bind(sock,(struct sockaddr *)&addr, sizeof(addr));
	if(n != 0){
		printf("bind fail\n");
		exit(0);
	}
	receiveDnsAnswer(sock);

}