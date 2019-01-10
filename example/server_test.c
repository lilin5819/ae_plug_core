#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include "../src/ae.h"
#include "../src/anet.h"

#define MAX_CLI 2
#define MAX_TIMER 2

typedef struct buf{
    uint16_t size;
    uint16_t len;
    char addr[0];
}buf_t;

typedef enum{
    SRV_TYPE_TCP = 0x01,
    SRV_TYPE_UNIX = 0x02,
    // SRV_TYPE_UNIX_TCP = 0x05
}SRV_TYPE;

typedef struct proto_st{
    aeEventLoop *loop;
    uint16_t hdr_len;
    uint32_t srv_type;
    struct {
        char ip[32];
        uint16_t port;
        int32_t fd;
    }tcp_srv;
    struct {
        int32_t enable;
        char path[32];
        int32_t fd;
    }unix_srv;
    uint16_t ntimer;
    struct {
        uint32_t enable;
        int32_t id;
        char name[32];
        int32_t interval;
        int32_t (*proc)(struct proto_st*proto,int32_t timer_idx,void *data);
    }timer[MAX_TIMER];
    uint32_t state;
    uint32_t next_state;
    int32_t (*init)(struct proto_st *proto,void* data);
    int32_t (*pkt_check)(struct proto_st *proto,buf_t*buf);
    buf_t* (*pack)(struct proto_st *proto,buf_t*buf);
    buf_t* (*unpack)(struct proto_st *proto,buf_t*buf);
    int32_t (*fsm)(struct proto_st *proto);
    int32_t (*send_msg)(struct proto_st *proto,int fd,void*addr,uint32_t len);
    int32_t (*recv_msg_cb)(struct proto_st *proto,int fd,void*addr,uint32_t len);
    int32_t (*close)(struct proto_st *proto);
    uint16_t ncli;
    struct {
        int32_t online;
        int32_t type;
        char ip[32];
        char unix_path[64];
        uint16_t port;
        int32_t fd;
    }cli[MAX_CLI];
    void *data;
    void *priv_data;
}proto_t;

buf_t *buf_dump(buf_t *buf)
{
    if(!buf) return NULL;
    buf_t *out_buf = malloc(sizeof(buf_t)+buf->len + 1);
    if(!out_buf) return NULL;

    out_buf->size = buf->len + 1;
    out_buf->len = buf->len;
    bzero(out_buf->addr,buf->len+1);
    memcpy(out_buf->addr,buf->addr,buf->len+1);
    return out_buf;
}

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
    buf_t *buf = proto->data,*out_buf = NULL;
    ssize_t i = 0,nread = 0 ,pkt_len = 0, nread_want = buf->size - buf->len;

    nread = read(fd, buf->addr + buf->len, nread_want);
    // printf("nread = %d,errno = %d\n",nread,errno);
    for(i =0 ;i<proto->ncli;i++)
        if(proto->cli[i].fd == fd)
            break;
    if(i >= proto->ncli)
    {
        printf("no such client fd %d\n",fd);
        return;
    }

    if (nread == -1) {
        if ((errno == EAGAIN || (errno == EINTR))) {
            /* Try again later */
            printf("busy , please read again !!\n");
            return;
        } else {
            printf("error ,Server closed the connection \n");
            aeDeleteFileEvent(loop, fd, AE_READABLE);
            buf->len = 0;
            bzero(buf->addr, buf->size);
            proto->cli[i].fd = -1;
            proto->cli[i].online = 0;
            close(fd);
            return;
        }
    } else if (nread == 0 ) {
        aeDeleteFileEvent(loop, fd, AE_READABLE);
        proto->cli[i].fd = -1;
        proto->cli[i].online = 0;
        printf("Server closed the connection \n");
        close(fd);
        return;
    } else {
        buf->len += nread;
    }

    if(proto->hdr_len > 0 && buf->len < proto->hdr_len)
        return;
    if(proto->pkt_check) {
unpack:
        pkt_len = proto->pkt_check(proto,proto->data);
        if( pkt_len < 0) {  // error pkt
            printf("pkt header error\n");
            buf->len = 0;
            bzero(buf->addr, buf->size);
        } else if(0 == pkt_len){  // not complete ; recv full pkt next time
            // printf("pkt not complete\n");
            return;
        } else { // complete pkt
            printf("pkt complete\n");
            out_buf = proto->unpack ? proto->unpack(proto,proto->data) : buf_dump(proto->data);
            if(proto->recv_msg_cb) {
                proto->recv_msg_cb(proto,fd,out_buf->addr,out_buf->len);
                if(proto->fsm)
                    proto->fsm(proto);
            }
            memcpy(buf->addr,buf->addr + pkt_len ,buf->len-pkt_len);
            buf->len = buf->len - pkt_len;
            bzero(buf->addr+buf->len, buf->size - buf->len);
            if(out_buf) {
                free(out_buf);
                out_buf = NULL;
            }
            if(proto->hdr_len && buf->len > proto->hdr_len)
                goto unpack;
        }
    } else { // no pkt check
        // printf("no need to check pkt\n");
        out_buf = proto->unpack ? proto->unpack(proto,proto->data) : buf_dump(proto->data);
        if(proto->recv_msg_cb) {
            proto->recv_msg_cb(proto,fd,out_buf->addr,out_buf->len);
            if(proto->fsm)
                proto->fsm(proto);
        }
        buf->len = 0;
        bzero(buf->addr, buf->size);
        if(out_buf) {
            free(out_buf);
            out_buf = NULL;
        }
    }
}

void acceptHandler(aeEventLoop *loop, int fd, void *clientdata, int mask)
{
    proto_t *proto = clientdata;
    int client_port, client_fd,i,cli_type = SRV_TYPE_UNIX;
    char client_ip[128];


    cli_type = (fd == proto->unix_srv.fd) ? SRV_TYPE_UNIX : SRV_TYPE_TCP;
    // create client socket
    if( SRV_TYPE_UNIX == cli_type)
        client_fd = anetUnixAccept(NULL, fd);
    else if(SRV_TYPE_TCP == cli_type)
        client_fd = anetTcpAccept(NULL, fd, client_ip, 128, &client_port);


    for(i =0 ;i<proto->ncli;i++)
        if(!proto->cli[i].online)
            break;
    if(i >= proto->ncli){
        printf("full client close fd:%d\n",client_fd);
        close(client_fd);
        return;
    }
    proto->cli[i].type = cli_type;
    proto->cli[i].fd = client_fd;
    proto->cli[i].online = 1;

    if(SRV_TYPE_UNIX == cli_type) {
        sprintf(proto->cli[i].unix_path,"%s",proto->unix_srv.path);
        printf("Accepted fd:%d unix:%s\n",client_fd, proto->unix_srv.path);
    } else {
        sprintf(proto->cli[i].ip,"%s",client_ip);
        proto->cli[i].port = client_port;
        printf("Accepted fd:%d tcp:%s:%d\n",client_fd, client_ip, client_port);
    }

    // set client socket non-block
    anetNonBlock(NULL, client_fd);
    // regist on message callback
    int ret;
    ret = aeCreateFileEvent(loop, client_fd, AE_READABLE, readFromClient, proto);
    assert(ret != AE_ERR);

    if(proto->init)
        proto->init(proto,(void*)client_fd);
}

int timer_proc(struct aeEventLoop *loop, long long id, void *clientData)
{
    int ret,i = 0;
    proto_t *proto = clientData;

    for(i = 0; i < proto->ntimer; i++)
        if(id == proto->timer[i].id)
            break;
    if(i < proto->ntimer)    
        ret = proto->timer[i].proc(proto,id,NULL);

    if(ret < 0)
        return AE_NOMORE;
    else
        return proto->timer[i].interval;
}

void timer_done(struct aeEventLoop *loop,void *clientData)
{
    printf("timer_done\n");
}

uint32_t run_server(struct proto_st *proto)
{
    int ret = 0,i = 0;
    if(SRV_TYPE_UNIX & proto->srv_type) {
        remove(proto->unix_srv.path);
        proto->unix_srv.fd = anetUnixServer(NULL, proto->unix_srv.path, 0, 0);
        assert(proto->unix_srv.fd != ANET_ERR);
        ret = aeCreateFileEvent(proto->loop, proto->unix_srv.fd, AE_READABLE, acceptHandler, proto);
        assert(ret != AE_ERR);
        printf("init unix server!!! fd:%d UNIX:%s\n",proto->tcp_srv.fd,proto->unix_srv.path);
    }
    if(SRV_TYPE_TCP & proto->srv_type) {
        proto->tcp_srv.fd = anetTcpServer(NULL, proto->tcp_srv.port, proto->tcp_srv.ip, 0);
        assert(proto->tcp_srv.fd != ANET_ERR);
        ret = aeCreateFileEvent(proto->loop, proto->tcp_srv.fd, AE_READABLE, acceptHandler, proto);
        assert(ret != AE_ERR);
        printf("init tcp server!!! fd:%d TCP:%s:%d\n",proto->tcp_srv.fd,proto->tcp_srv.ip,proto->tcp_srv.port);
    }

    
    for(i = 0; i < proto->ntimer; i++)
    {
        printf("init timer %d,enable:%d\n",i,proto->timer[i].enable);
        if(proto->timer[i].enable)
            proto->timer[i].id = aeCreateTimeEvent(proto->loop, proto->timer[i].interval, timer_proc, proto, timer_done);
    }
    
    // start main loop
    aeMain(proto->loop);

    // stop loop
    aeDeleteEventLoop(proto->loop);
}




static int32_t timer_check_proc(struct proto_st*proto,int32_t timer_idx,void *data)
{
    int i = 0;

    for(i = 0 ;i < proto->ncli;i++)
    {
        // printf("client[%d] online=%d fd=%d\n",i,proto->cli[i].online,proto->cli[i].fd);
        if(proto->cli[i].online > 0) { // client online
            char buffer[128] = {0};
            if(SRV_TYPE_UNIX == proto->cli[i].type)
                sprintf(buffer,"timer:%lld - Hello client[%d]!! from server unix:%s \n", proto->timer[timer_idx].id,i,proto->unix_srv.path);
            else
                sprintf(buffer,"timer:%lld - Hello client[%d]!! from server tcp:%s:%d \n", proto->timer[timer_idx].id,i,proto->tcp_srv.ip,proto->tcp_srv.port);
            // printf("client send fd:%d :%d:%s\n",proto->cli[i].fd,strlen(buffer),buffer);
            anetWrite(proto->cli[i].fd,buffer,strlen(buffer));
        }
    }
    // return AE_NOMORE;
    return 0;
}

static int32_t init_demo(struct proto_st *proto,void* data)
{
    char buf[128] = {0};
    int fd = (int)data;
    int id = 0;

    printf("init_demo\n");

    if(fd == proto->unix_srv.fd)
        sprintf(buf,"hello unix:%s\n",proto->unix_srv.path);
    else if(fd == proto->tcp_srv.fd)
        sprintf(buf,"hello tcp:%s:%d\n",proto->cli[0].ip,proto->cli[0].port);
    proto->send_msg(proto,fd,buf,strlen(buf));
}

static int32_t pkt_check_demo(struct proto_st *proto,buf_t*buf)
{
    // printf("pkt_check_demo :%d\n",buf->len);
    return buf->len < 8 ? 0 : 8; // 4 bytes hdr 4 bytes payload
}

static buf_t* pack_demo(struct proto_st *proto,buf_t*buf)
{
    printf("pack_demo\n");
    return buf_dump(buf);
}

static buf_t* unpack_demo(struct proto_st *proto,buf_t*buf)
{
    printf("unpack_demo\n");
    buf_t *out_buf = buf_dump(buf);
    if(!out_buf) return NULL;

    if(proto->pkt_check) {
        out_buf->len = 8;
    } else {
        out_buf->len = buf->len;
    }
    out_buf->addr[8] = 0;
    return out_buf;
}

static int32_t send_msg_demo(struct proto_st *proto,int fd,void*addr,uint32_t len)
{
    return anetWrite(fd,addr,len);
}

static int32_t recv_msg_cb_demo(struct proto_st *proto,int fd,void*addr,uint32_t len)
{
    printf("recv_msg_cb_demo :%d:%s\n",len,addr);
    proto->next_state ++;
}

static int32_t fsm_demo(struct proto_st *proto)
{
    printf("fsm_demo : cur_stat=%d;next_stat:%d\n",proto->state,proto->next_state);
    proto->state = proto->next_state;
}


int main()
{
    buf_t *buf = NULL;
    proto_t proto = {
        .loop = aeCreateEventLoop(1024),
        .srv_type = SRV_TYPE_UNIX | SRV_TYPE_TCP ,
        .tcp_srv = {
            .ip = "0.0.0.0",
            .port = 8000,
            .fd = -1,
        },
        .unix_srv = {
            .path = "/tmp/libae.sock",
            .fd = -1,
        },
        .ncli = MAX_CLI,
        .ntimer = MAX_TIMER,
        .timer = {
            [0] = {
                .enable = 1,
                .id = 0,
                .name = "1s timer",
                .interval = 1*1000,
                .proc = timer_check_proc,
            },
            [1] = {
                .enable = 1,
                .id = 1,
                .name = "5s timer",
                .interval = 5*1000,
                .proc = timer_check_proc,
            },
        },
        .hdr_len = 4,
        .init = init_demo,
        .pkt_check = pkt_check_demo,
        .pack = pack_demo,
        .unpack = unpack_demo,
        .send_msg = send_msg_demo,
        .recv_msg_cb = recv_msg_cb_demo,
        .fsm = fsm_demo
    };
    buf = malloc(sizeof(buf_t)+1024);
    memset(buf,0,sizeof(buf_t)+1024);
    proto.data = buf; 
    buf->size = 1024;
    // printf("proto.srv_type=%d\n",proto.srv_type);
    // printf("proto.tcp_srv.ip=%s\n",proto.tcp_srv.ip);
    // printf("proto.tcp_srv.port=%d\n",proto.tcp_srv.port);
    // printf("proto.unix_srv.path=%s\n",proto.unix_srv.path);
    // printf("proto.init=%p\n",proto.init);
    // printf("proto.pkt_check=%p\n",proto.pkt_check);
    // printf("proto.unpack=%p\n",proto.unpack);
    // printf("proto.pack=%p\n",proto.pack);
    // printf("proto.send_msg=%p\n",proto.send_msg);
    // printf("proto.recv_msg_cb=%p\n",proto.recv_msg_cb);
    // printf("proto.fsm=%p\n",proto.fsm);
    run_server(&proto);
    free(proto.data);

    return 0;
}
