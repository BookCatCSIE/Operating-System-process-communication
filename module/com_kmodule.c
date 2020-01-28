#include "com_kmodule.h"
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/init.h>
#include <linux/pid.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
//#define NETLINK_TEST 30
#define NETLINK_USER 31
//#define NETLINK_USER 0
#define MAX_PAYLOAD 1024

#define MSG_LEN 255
#define USER_PORT 100

struct sock *nlsk = NULL;
extern struct net init_net;

int send_usrmsg(char *pbuf, uint16_t len)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;
    int ret;

    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if(!nl_skb)
    {
        printk("netlink alloc failure\n");
        return -1;
    }

    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_USER, len, 0);
    if(nlh == NULL)
    {
        printk("nlmsg_put failaure \n");
        nlmsg_free(nl_skb);
        return -1;
    }

    memcpy(nlmsg_data(nlh), pbuf, len);
    ret = netlink_unicast(nlsk, nl_skb, USER_PORT, MSG_DONTWAIT);
    return ret;
}


static void netlink_rcv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    char *umsg = NULL;
    //kmsg -> send to user
    char *kmsg = "Success";
    if(skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        umsg = NLMSG_DATA(nlh);
        if(umsg)
        {
            printk("kernel recv from user: %s\n", umsg);
            send_usrmsg(kmsg, strlen(kmsg));
        }
    }
}


struct netlink_kernel_cfg cfg =
{
    .groups = 0,
    .input  = netlink_rcv_msg, /* set recv callback */
};


static int __init com_kmodule_init(void)
{
    printk(KERN_INFO "Enter module. Hello world!\n");
    /* create netlink socket */
    nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if(nlsk == NULL)
    {
        printk("netlink_kernel_create error !\n");
        return -1;
    }
    printk("test_netlink_init\n");
    return 0;
}

static void __exit com_kmodule_exit(void)
{
    if (nlsk)
    {
        netlink_kernel_release(nlsk); //sock_release(nl_sk->sk_socket);
        nlsk = NULL;
    }
    printk("test_netlink_exit!\n");
    printk(KERN_INFO "Exit module. Bye~\n");
}



module_init(com_kmodule_init);
module_exit(com_kmodule_exit);
