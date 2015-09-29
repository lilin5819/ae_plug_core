#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include "../src/ae.h"
#include "../src/anet.h"

typedef struct buf{
    uint32_t size;
    uint32_t len;
    char addr[0];
}buf_t;

typedef enum{
    SRV_TYPE_TCP,
    SRV_TYPE_UDP,
    SRV_TYPE_UNIX
}SRV_TYPE;

typedef struct proto_st{
    aeEventLoop *loop;
    uint32_t hdr_len;
    uint32_t fd;
    struct {
        uint32_t type;
        char ip[32];
        uint16_t port;
        char unix_path[32];
    }srv;
    struct {
        char ip[32];
        uint16_t port;
        uint32_t fd;
    }cli;
    uint32_t fsm_cur_stat;
    uint32_t fsm_next_stat;
    uint32_t (*init)(struct proto_st *proto,char *ipstr,uint16_t port,uint32_t fd);
    uint32_t (*pkt_check)(struct proto_st *proto,buf_t*buf);
    buf_t* (*pack)(struct proto_st *proto,buf_t*buf);
    buf_t* (*unpack)(struct proto_st *proto,buf_t*buf);
    uint32_t (*fsm)(struct proto_st *proto);
    uint32_t (*send_msg)(struct proto_st *proto,int fd,void*addr,uint32_t len);
    uint32_t (*recv_msg_cb)(struct proto_st *proto,int fd,void*addr,uint32_t len);
    uint32_t (*close)(struct proto_st *proto);
    buf_t *buf;
    void *priv_data;
}proto_t;

void writeToClient(aeEventLoop *loop, int fd, void *clientdata, int mask)
{
    buf_t *buf = clientdata;
    printf("writeToClient %d\n",buf->len);
    anetWrite(fd,buf->addr,buf->len);
    if(buf)
        free(buf);
    aeDeleteFileEvent(loop, fd, AE_WRITABLE);
}

void readFromClient(aeEventLoop *loop, int fd, void *clientdata, int mask)
{
    proto_t *proto = clientdata;
    buf_t *buf = proto->buf,*out_buf = NULL;
    ssize_t nread = 0 ,pkt_len = 0, nread_want = buf->size - buf->len;
    nread = read(fd, buf->addr + buf->len, nread_want);
    // printf("nread = %d,errno = %d\n",nread,errno);

    if (nread == -1) {
        if ((errno == EAGAIN || (errno == EINTR))) {
            /* Try again later */
            printf("busy , please read again !!\n");
            return;
        } else {
            aeDeleteFileEvent(loop, fd, AE_READABLE);
            buf->len = 0;
            bzero(buf->addr, buf->size);
            return;
        }
    } else if (nread == 0 ) {
        aeDeleteFileEvent(loop, fd, AE_READABLE);
        printf("Server closed the connection \n");
        return;
    } else {
        buf->len += nread;
        // aeCreateFileEvent(loop, fd, AE_WRITABLE, writeToClient, buffer);
    }

    if(buf->len < proto->hdr_len) {
        // printf("recved pkt len less than header\n");
        return;
    }
    if(proto->pkt_check) {
unpack:
        pkt_len = proto->pkt_check(proto,proto->buf);
        if( pkt_len < 0) {  // error pkt
            printf("pkt header error\n");
            buf->len = 0;
            bzero(buf->addr, buf->size);
        } else if(0 == pkt_len){  // not complete ; recv full pkt next time
            // printf("pkt not complete\n");
            return;
        } else { // complete pkt
            printf("pkt complete\n");
            out_buf = proto->unpack ? proto->unpack(proto,proto->buf) : proto->buf;
            if(proto->recv_msg_cb) {
                proto->recv_msg_cb(proto,fd,out_buf->addr,out_buf->len);
                if(proto->fsm)
                    proto->fsm(proto);
            }
            memcpy(buf->addr,buf->addr + pkt_len ,buf->len-pkt_len);
            buf->len = buf->len - pkt_len;
            bzero(buf->addr+buf->len, buf->size - buf->len);
            if(proto->unpack && out_buf) {
                free(out_buf);
                out_buf = NULL;
            }
            if(proto->hdr_len && buf->len > proto->hdr_len)
                goto unpack;
        }
    } else { // no pkt check
        // printf("no need to check pkt\n");
        out_buf = proto->unpack ? proto->unpack(proto,proto->buf) : proto->buf;
        if(proto->recv_msg_cb) {
            proto->recv_msg_cb(proto,fd,out_buf->addr,out_buf->len);
            if(proto->fsm)
                proto->fsm(proto);
        }
        buf->len = 0;
        bzero(buf->addr, buf->size);
        if(proto->unpack && out_buf) {
            free(out_buf);
            out_buf = NULL;
        }
    }
}

void acceptTcpHandler(aeEventLoop *loop, int fd, void *clientdata, int mask)
{
    proto_t *proto = clientdata;
    int client_port, client_fd;
    char client_ip[128];
    // create client socket
    client_fd = anetTcpAccept(NULL, fd, client_ip, 128, &client_port);
    printf("Accepted %s:%d\n", client_ip, client_port);

    // set client socket non-block
    anetNonBlock(NULL, client_fd);
    // regist on message callback
    int ret;
    ret = aeCreateFileEvent(loop, client_fd, AE_READABLE, readFromClient, proto);
    assert(ret != AE_ERR);

    if(proto->init)
        proto->init(proto,client_ip,client_port,client_fd);
}

uint32_t run_server(struct proto_st *proto)
{
    int ret = 0;
    if(SRV_TYPE_UNIX == proto->srv.type)
        proto->fd = anetUnixServer(NULL, proto->srv.unix_path, 0, 0);
    else
        proto->fd = anetTcpServer(NULL, proto->srv.port, proto->srv.ip, 0);
    assert(proto->fd != ANET_ERR);
    ret = aeCreateFileEvent(proto->loop, proto->fd, AE_READABLE, acceptTcpHandler, proto);
    assert(ret != AE_ERR);

    // start main loop
    aeMain(proto->loop);

    // stop loop
    aeDeleteEventLoop(proto->loop);
}


static uint32_t init_demo(struct proto_st *proto,char *ipstr,uint16_t port,uint32_t fd)
{
    char buf[128] = {0};
    printf("init_demo\n");
    sprintf(proto->cli.ip,"%s",ipstr);
    proto->cli.port = port;
    proto->cli.fd = fd;
    sprintf(buf,"hello world! %s:%d\n",ipstr,port);
    proto->send_msg(proto,fd,buf,strlen(buf));
}

static uint32_t pkt_check_demo(struct proto_st *proto,buf_t*buf)
{
    // printf("pkt_check_demo :%d\n",buf->len);
    return buf->len < 8 ? 0 : 8; // 4 bytes hdr 4 bytes payload
}

static buf_t* pack_demo(struct proto_st *proto,buf_t*buf)
{
    printf("pack_demo\n");
    return buf;
}

static buf_t* unpack_demo(struct proto_st *proto,buf_t*buf)
{
    printf("unpack_demo\n");
    buf_t *out_buf = malloc(sizeof(buf_t)+1024);
    if(!out_buf) return NULL;
    bzero(out_buf->addr,1024);
    out_buf->size = 1024;

    if(proto->pkt_check) {
        memcpy(out_buf->addr,buf->addr,proto->pkt_check(proto,buf));
        out_buf->len = 8;
    } else {
        memcpy(out_buf->addr,buf->addr,buf->len);
        out_buf->len = buf->len;
    }
    return out_buf;
}

static uint32_t send_msg_demo(struct proto_st *proto,int fd,void*addr,uint32_t len)
{
    buf_t *buf = malloc(sizeof(buf_t)+1024);
    bzero(buf,sizeof(buf_t)+1024);
    buf->size = 1024;
    buf->len = len;
    memcpy(buf->addr,addr,len);
    printf("send_msg_demo : send:%d:%s\n",len,addr);
    aeCreateFileEvent(proto->loop, fd, AE_WRITABLE, writeToClient, buf);

    // return anetWrite(fd,addr,len);
}

static uint32_t recv_msg_cb_demo(struct proto_st *proto,int fd,void*addr,uint32_t len)
{
    printf("recv_msg_cb_demo : recvd:%d:%s\n",len,addr);
    proto->fsm_next_stat ++;
}

static uint32_t fsm_demo(struct proto_st *proto)
{
    printf("fsm_demo : cur_stat=%d;next_stat:%d\n",proto->fsm_cur_stat,proto->fsm_next_stat);
    proto->fsm_cur_stat = proto->fsm_next_stat;
}



int main()
{
    proto_t proto = {
        .loop = aeCreateEventLoop(1024),
        .srv.ip = "0.0.0.0",
        .srv.port = 8000,
        .srv.unix_path = "/var/libae.log",
        .hdr_len = 4,
        .init = init_demo,
        .pkt_check = pkt_check_demo,
        .pack = pack_demo,
        .unpack = unpack_demo,
        .send_msg = send_msg_demo,
        .recv_msg_cb = recv_msg_cb_demo,
        .fsm = fsm_demo
    };
    proto.buf = malloc(sizeof(buf_t)+1024);
    memset(proto.buf,0,1024);
    proto.buf->size = 1024;
    printf("proto.srv.ip=%s\n",proto.srv.ip);
    printf("proto.srv.port=%d\n",proto.srv.port);
    printf("proto.init=%p\n",proto.init);
    printf("proto.pkt_check=%p\n",proto.pkt_check);
    printf("proto.unpack=%p\n",proto.unpack);
    printf("proto.pack=%p\n",proto.pack);
    printf("proto.send_msg=%p\n",proto.send_msg);
    printf("proto.recv_msg_cb=%p\n",proto.recv_msg_cb);
    printf("proto.fsm=%p\n",proto.fsm);

    run_server(&proto);

    return 0;
}
