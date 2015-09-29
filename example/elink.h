#define SOCKET_TYPE_GW 1
#define SOCKET_TYPE_SDK 2
#define ELINK_UNIX_SOCKET "/tmp/ctc_elinkap.sock"

#define WL_2G_11B 1
#define WL_2G_11G 2
#define WL_2G_11BG 3
#define WL_2G_11N 8
#define WL_2G_11BN 9
#define WL_2G_11GN 10
#define WL_2G_11BGN 11

#define WL_5G_11A 4
#define WL_5G_11N 8
#define WL_5G_11AN 12
#define WL_5G_11AC 64
#define WL_5G_11AAC 68
#define WL_5G_11NAC 72
#define WL_5G_11ANAC 76

#define TPI_IP_STRING_LEN 32

/*
        E-link proto state define.

*/
typedef enum ELINK_STAT
{
    ELINK_STATE_RESET = 0, // State For clear and delay jobs.
    ELINK_STATE_INIT,
    ELINK_STATE_CONNECT,
    ELINK_STATE_KEYNGREQ,
    ELINK_STATE_DH,
    ELINK_STATE_DEV_REG,
    ELINK_STATE_MSG_LOOP,
    ELINK_STATE_MAX
} ELINK_STAT;

typedef enum WAN_STAT
{
    WAN_STAT_DOWN = 0,
    WAN_STAT_UP,
    WAN_STAT_CHANGE_IP,
    WAN_STAT_NET_OK,
} WAN_STAT;

/*elink version*/
#define ELINK_VERSION "V2018.1.0"

/*
        E-link proto timer define. See protocol.
*/
#define DELAY_T1 (5)
#define DELAY_T2 (10)
#define DELAY_T3 (20)
#define DELAY_T4 (20)
#define DELAY_T5 (5)
#define DELAY_T6 (5)
#define DELAY_T7 (5)
#define DELAY_T8 (2)
#define DELAY_T9 (5)

/*
        E-link proto, GateWay Listen PORT.
*/
#define ELINK_GATEWAY_PORT (32768)

/*
        E-link proto Header struct.
*/

#define ELINK_HEADER_LENGTH (8)
#define ELINK_HEADER_MAGIC (0x3f721fb5)

#define MOD_16_INTGER(num) (num + (16 - num % 16) % 16)

/*
        E-link proto Message type string.
*/
#define ELINK_MSG_KEYNGREQ "keyngreq"
#define ELINK_MSG_KEYNGACK "keyngack"
#define ELINK_MSG_DH "dh"
#define ELINK_MSG_DEV_REG "dev_reg"
#define ELINK_MSG_ACK "ack"
#define ELINK_MSG_KEEPALIVE "keepalive"
#define ELINK_MSG_CFG "cfg"
#define ELINK_MSG_GET_STATUS "get_status"
#define ELINK_MSG_STATUS "status"
#define ELINK_MSG_DEV_REPORT "dev_report"
#define ELINK_MSG_WAN_REPORT "wan_report"
#define ELINK_MSG_GETRSSIINFO "getrssiinfo"
#define ELINK_MSG_RSSIINFO "rssiinfo"
#define ELINK_MSG_DEASSOCIATION "deassociation"

#define ELINK_MSG_CFG_WIFI "wifi"
#define ELINK_MSG_CFG_WIFISWITCH "wifiswitch"
#define ELINK_MSG_CFG_LEDSWITCH "ledswitch"
#define ELINK_MSG_CFG_WIFITIMER "wifitimer"
#define ELINK_MSG_CFG_WPSSWITCH "wpsswitch"
#define ELINK_MSG_CFG_UPGRADE "upgrade"
#define ELINK_MSG_CFG_CTRLCOMMAND "ctrlcommand"
#define ELINK_MSG_CFG_ROAMING_SET "roaming_set"
#define ELINK_MSG_CFG_ROAMING_REPORT "roaming_report"

#define ELINK_MSG_GET_STATUS_WIFI "wifi"
#define ELINK_MSG_GET_STATUS_WIFISWITCH "wifiswitch"
#define ELINK_MSG_GET_STATUS_LEDSWITCH "ledswitch"
#define ELINK_MSG_GET_STATUS_WIFITIMER "wifitimer"
#define ELINK_MSG_GET_STATUS_BANDSUPPORT "bandsupport"
#define ELINK_MSG_GET_STATUS_CPURATE "cpurate"
#define ELINK_MSG_GET_STATUS_MEMORYUSERATE "memoryuserate"
#define ELINK_MSG_GET_STATUS_UPLOADSPEED "uploadspeed"
#define ELINK_MSG_GET_STATUS_DOWNLOADSPEED "downloadspeed"
#define ELINK_MSG_GET_STATUS_WLANSTATS "wlanstats"
#define ELINK_MSG_GET_STATUS_CHANNEL "channel"
#define ELINK_MSG_GET_STATUS_ONLINETIME "onlineTime"
#define ELINK_MSG_GET_STATUS_TERMINALNUM "terminalNum"
#define ELINK_MSG_GET_STATUS_LOAD "load"
#define ELINK_MSG_GET_STATUS_REAL_DEVINFO "real_devinfo"
#define ELINK_MSG_GET_STATUS_ELINKSTAT "elinkstat"
#define ELINK_MSG_GET_STATUS_NEIGHBORINFO "neighborinfo"
#define ELINK_MSG_GET_STATUS_NETWORKTYPE "networktype"
#define ELINK_MSG_GET_STATUS_WORKMODE "workmode"
