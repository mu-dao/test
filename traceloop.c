//#define __FAVOR_BSD
#include"trace.h"

int gotalarm;

const char *icmpcode_v4(int code){
    static char errbuf[100];
    switch(code){
        case 0:return("network unreachable");   
        case 1:return("host unreachable");
        case 2:return("protocol unreachable");
        case 3:return("port unreachable");  
        case 4:return("fragmentation required but DF bit set"); 
        case 5:return("source route failed");   
        case 6:return("destination network unknown");   
        case 7:return("destination host unknown");  
        case 8:return("source host isolated(obsolete)");    
        case 9:return("destination network administartively prohibited");
        case 10:return("destination host administartively prohibited"); 
        case 11:return("network unreachable for TOS");  
        case 12:return("host unreachable for TOS"); 
        case 13:return("communication error");  
        case 14:return("host recedenc violation");  
        case 15:return("precedence cutoff in effect");  
        default:sprintf(errbuf,"unknown code %d",code);
    }   
    return errbuf;  
}

void sig_alrm(int signo){
    gotalarm=1;
    return;
}

void tv_sub(struct timeval *out,struct timeval *in){
    if((out->tv_usec-=in->tv_usec)<0){
        --out->tv_sec;
        out->tv_sec+=1000000;
    }   
    out->tv_sec-=in->tv_sec;
}

void traceloop(void){
    int seq,code,done;
    double rtt;
    struct rec *rec;
    struct timeval tvrecv;

	//创建套接字
    if((recvfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto)) < 0){
        printf("recvfd:socket failed\n");
        return;
    }
    setuid(getuid());

    if((sendfd = socket(pr->sasend->sa_family, SOCK_DGRAM, 0)) < 0){
        printf("sendfd:socket failed\n");
        return;
    }

    pr->sabind->sa_family = pr->sasend->sa_family;
    sport = (getpid() & 0xffff) | 0x8000;
    ((struct sockaddr_in*)pr->sabind)->sin_port = htons(sport);

    if(bind(sendfd, pr->sabind, pr->salen) < 0){
        printf("bind error\n");
        return;
    }

    sig_alrm(SIGALRM);
    seq = 0;
    done = 0;

    for(ttl = 1; ttl <= max_ttl && done == 0; ttl++){
        setsockopt(sendfd, pr->ttllevel, pr->ttloptname, &ttl, sizeof(int));//modify ttl
        bzero(pr->salast, pr->salen);
        printf("%2d ", ttl);
        fflush(stdout);
        for(probe = 0; probe < nprobes; probe++){
            /*
            *these sendbuf is just
            *used to exam if the received data is sended by our program 
            */
            rec = (struct rec*)sendbuf;
            rec->rec_seq = ++seq;
            rec->rec_ttl = ttl;

            gettimeofday(&rec->rec_tv, NULL);
            ((struct sockaddr_in*)pr->sasend)->sin_port = htons(dport + seq);
            if(sendto(sendfd, sendbuf, datalen, 0, pr->sasend, pr->salen) < 0){//send to dest with ttl added
                perror("bad sendto");
                continue;
            }

            //if time_out print * else print info
            if((code = (*pr->recv)(seq, &tvrecv)) == -3){
                printf(" *");
            }else{
                char str[NI_MAXHOST];
                if(memcmp(pr->sarecv, pr->salast, pr->salen) != 0){
                    if(getnameinfo(pr->sarecv, pr->salen, str, sizeof(str), NULL, 0, 0) == 0){
                        printf(" %s (%s)", str, inet_ntoa(((struct sockaddr_in*)pr->sarecv)->sin_addr));
                    }else{
                        printf(" %s", inet_ntoa(((struct sockaddr_in*)pr->sarecv)->sin_addr));
                    }
                    memcpy(pr->salast, pr->sarecv, pr->salen);
                }
                tv_sub(&tvrecv, &rec->rec_tv);
                rtt = tvrecv.tv_sec * 1000.0 + tvrecv.tv_usec/1000;
                printf("  %.3f ms", rtt);

                if(code == -1){   //reach the dest
                    done++;
                }else if(code > 0){
                    printf(" (ICMP %s)",(*pr->icmpcode)(code));
                }
            }
            fflush(stdout);
        }
        printf("\n");
    }
	if(ttl == max_ttl + 1 && done == 0){
		printf("Can't reach dest ip!\n\n");
	}
}

int recv_v4(int seq, struct timeval *tv){
    int				hlen1, hlen2, icmplen, ret;
    socklen_t		len;
    ssize_t			n;
    struct ip		*ip, *hip;
    struct icmp		*icmp;
    struct udphdr	*udp;

    gotalarm = 0;

    for(;;){
        if(gotalarm){
            return -3;
        }
        len = pr->salen;
        alarm(3);
        n = recvfrom(recvfd,recvbuf,sizeof(recvbuf),0,pr->sarecv,&len);//data len
        if(n < 0){
            if(errno == EINTR){
                continue;
            }else{
                printf("recvfrom error\n");
                return 0;
            }
        }else{
            //if recvfrom ok , close the alarm
            alarm(0);
        }

        //read data
        ip = (struct ip*) recvbuf;

		/* IP报文首部长度 = 长度标识 * 4
		 * 一般IP报文首部为20字节，但如果有“选项”字段，那么最大可达60字节
		 * 因此IP报文首部长度通过长度标识来计算才是准确的
		 */
        hlen1 = ip->ip_hl << 2; 
		
		//越过IP首部，ICMP报文从这个位置开始
 		icmp = (struct icmp*)(recvbuf + hlen1);

		//整个ICMP报文长度 = ICMP首部8字节 + 产生出错的IP首部 + UDP首部8字节
		icmplen = n - hlen1;
        
		//如果长度小于8字节，说明当前收到的报文肯定不是UDP不可达报文
		if(icmplen < 8){
            continue;
        }

		/* ICMP_TIMXCEED 表示 超时
		 * ICMP_TIMXCEED_INTRANS 表示传输过程中，TTL已变为0
		 */
        if(icmp->icmp_type == ICMP_TIMXCEED &&
           icmp->icmp_code == ICMP_TIMXCEED_INTRANS){
			//如果长度小于ICMP首部8字节 + IP首部，也说明不是UDP不可达报文
            if(icmplen < 8 + sizeof(struct ip)){
                continue;
            }

			//指向产生出错的IP报文
            hip = (struct ip*)(recvbuf + hlen1 + 8);
            hlen2 = hip->ip_hl << 2;
            
			//再排除掉长度小于ICMP首部 + IP首部 + UDP首部的情况
			//if(icmplen < 8 + hlen2 + 4){
            if(icmplen < 8 + hlen2 + 8){
				continue;
            }

			//指向UDP首部
            udp = (struct udphdr *)(recvbuf + hlen1 + 8 + hlen2);
            
			if(hip->ip_p == IPPROTO_UDP&&
               udp->source == htons(sport)&&
               udp->dest == htons(dport+seq)){
                ret = -2;
                break;
            }
        }
		/* ICMP_UNREACH 表示目标不可达
		*/	
		else if(icmp->icmp_type == ICMP_UNREACH){
            if(icmplen < 8 + sizeof(struct ip))
                continue;

            hip = (struct ip*)(recvbuf + hlen1 + 8);
            hlen2 = hip->ip_hl << 2;
            //if(icmplen < 8 + hlen2 + 4)
			if(icmplen < 8 + hlen2 + 8)
                continue;
            
			udp = (struct udphdr*)(recvbuf + hlen1 + 8 + hlen2);

            if(hip->ip_p == IPPROTO_UDP&&
               udp->source == htons(sport)&&
               udp->dest == htons(dport+seq)){
                if(icmp->icmp_code == ICMP_UNREACH_PORT)
                    ret = -1;     //reach the destination
                else
                    ret = icmp->icmp_code;
                break;
            }
        }
    }
    gettimeofday(tv, NULL);
    return ret;
}
