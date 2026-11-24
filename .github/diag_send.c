#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
int main(void){
  int l=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a;memset(&a,0,sizeof a);a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  bind(l,(void*)&a,sizeof a);listen(l,1);socklen_t len=sizeof a;getsockname(l,(void*)&a,&len);
  int c=socket(AF_INET,SOCK_STREAM,0);int small=4096;setsockopt(c,SOL_SOCKET,SO_SNDBUF,&small,sizeof small);
  connect(c,(void*)&a,sizeof a);int p=accept(l,0,0);setsockopt(p,SOL_SOCKET,SO_RCVBUF,&small,sizeof small);
  static char buf[256<<10];double t0=now();long calls=0,partial=0,eagain=0,pollrdy=0,pollto=0;long long total=0;
  while(now()-t0<5){
    ssize_t r=send(c,buf,sizeof buf,MSG_DONTWAIT);calls++;
    if(r<0){ if(errno==EAGAIN){eagain++;struct pollfd pf={c,POLLOUT,0};int pr=poll(&pf,1,50);if(pr>0)pollrdy++;else pollto++;} else {printf("errno %d\n",errno);break;} }
    else {partial++;total+=r;}
  }
  printf("5s: calls=%ld sends_ok=%ld eagain=%ld poll_ready=%ld poll_timeout=%ld bytes=%lld\n",calls,partial,eagain,pollrdy,pollto,total);
  return 0;}
