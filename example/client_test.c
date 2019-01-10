#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "../src/ae.h"
#include "../src/anet.h"
int ipfd;

void readFromServer(aeEventLoop *loop, int fd, void *clientdata, int mask)
{
    int buffer_size = 1024;
    char *buffer = malloc(sizeof(char) * buffer_size);
    bzero(buffer, buffer_size);
    int size;
    size = read(fd, buffer, buffer_size);
    if(size > 0)
    {
        printf("client recv:%d:%s\n",size,buffer);
        // aeCreateFileEvent(loop, fd, AE_WRITABLE, writeToServer, buffer);
    }
}

int timer_hello(struct aeEventLoop *loop, long long id, void *clientData)
{
    int ret;
    char buffer[128] = {0};
    sprintf(buffer,"%lld - Hello, World\n", id);
    printf("client send:%d:%s\n",strlen(buffer),buffer);

    anetWrite(ipfd,buffer,strlen(buffer));
    assert(ret != ANET_ERR);
    return -1;
}

void timer_hello_done(struct aeEventLoop *loop,void *clientData)
{
    printf("timer_hello_done\n");
}

int main()
{
    int ret;
    aeEventLoop *loop;
    loop = aeCreateEventLoop(20);

    ipfd = anetTcpNonBlockConnect(NULL,"127.0.0.1",8000);
    // ipfd = anetUnixConnect(NULL,"/tmp/libae.sock");
    assert(ipfd != ANET_ERR);
    printf("connect ok\n");

    ret = aeCreateFileEvent(loop, ipfd, AE_READABLE, readFromServer, NULL);
    assert(ret != ANET_ERR);

    int i;
    for (i = 0; i < 10; i ++) {
        aeCreateTimeEvent(loop, i*1000, timer_hello, NULL, timer_hello_done);
    }

    aeMain(loop);

    aeDeleteEventLoop(loop);

    return 0;
}
