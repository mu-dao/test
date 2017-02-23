#include"trace.h"
struct proto proto_v4 = {icmpcode_v4,recv_v4,NULL,NULL,NULL,NULL,0,IPPROTO_ICMP,IPPROTO_IP,IP_TTL};

int datalen = sizeof(struct rec);
int max_ttl = 6;
int nprobes = 3;
u_short dport = 32768+666;//hope the port of dest is not used

struct addrinfo *host_serv(const char *host, const char *serv, int family, int socktype){
    int n;
    struct addrinfo hints, *res;
    bzero(&hints, sizeof(hints));
    hints.ai_flags    = AI_CANONNAME;
    hints.ai_family   = family;
    hints.ai_socktype = socktype;
    if((n = getaddrinfo(host, serv, &hints, &res)) != 0){
        return NULL;
    }
    return (res);
}


int main(int argc,char *argv[]){
    int c;
    struct addrinfo *ai;
    struct sigaction s_action;
    char h[20] = {0};
    while((c = getopt(argc,argv,"m:v")) != -1){
        switch(c){
            case 'm':
                if((max_ttl = atoi(optarg)) < 0){
                    printf("invalid input\n");
                }
                break;
            case 'v':
                verbose++;
                break;
            case '?':
                printf("unrecognized\n");
                return -1; 
        }   
    }   
    if(optind != argc - 1){
        printf("error input\n");    
        return -1; 
    }  
    host = argv[optind];

    pid  = getpid();

    bzero(&s_action, sizeof(s_action));
    s_action.sa_handler = sig_alrm;
    s_action.sa_flags = SA_INTERRUPT;
    sigaction(SIGALRM, &s_action, NULL);

//  signal(SIGALRM,sig_alrm); 
    ai = host_serv(host,NULL,0,0);
    inet_ntop(AF_INET,&((struct sockaddr_in*)(ai->ai_addr))->sin_addr,h,sizeof(h));
    printf("traceroute to %s (%s): %d hops max, %d data bytes\n",
            ai->ai_canonname?ai->ai_canonname:h,h,max_ttl,datalen);

    if(ai->ai_family == AF_INET){
        pr = &proto_v4;
    }else{
        printf("UNKNOW address family\n");
        return -1;
    }

    pr->sasend = ai->ai_addr;
    pr->sarecv = (struct sockaddr*)calloc(1,ai->ai_addrlen);
    pr->salast = (struct sockaddr*)calloc(1,ai->ai_addrlen);
    pr->sabind = (struct sockaddr*)calloc(1,ai->ai_addrlen);
    pr->salen  = ai->ai_addrlen;
    traceloop();
    exit(0);
}
