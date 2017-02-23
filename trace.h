#include<stdio.h>
#include<sys/time.h>
#include<errno.h>
#include<signal.h>
#include<time.h>
#include<stdlib.h>
#include<unistd.h>
#include<netdb.h>
#include<string.h>
#include<strings.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h> //包含icmp结构体
#include<netinet/udp.h>
#include<netinet/in_systm.h>
#define BUFSIZE 1500

struct rec{
	u_short rec_seq;
	u_short rec_ttl;
	struct timeval rec_tv;
};

char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

int datalen;
char *host;
u_short sport,dport;
int nsent;
pid_t pid;
int probe,nprobes;
int sendfd,recvfd;
int ttl,max_ttl;
int verbose;

const char* icmpcode_v4(int);
int recv_v4(int,struct timeval*);
void sig_alrm(int);
void traceloop(void);
void tv_sub(struct timeval*,struct timeval*);

struct proto{
	const char*(*icmpcode)(int);
	int (*recv)(int,struct timeval*);
	struct sockaddr *sasend;    //dest addr, the destination
	struct sockaddr *sarecv;    //recv addr, store who send the message
	struct sockaddr *salast;
	struct sockaddr *sabind;    //bind the source port
	socklen_t salen;
	int icmpproto;
	int ttllevel;
	int ttloptname;
}*pr;
