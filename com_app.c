#include "com_app.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <asm/types.h>
#include <stdint.h>
#include <malloc.h>
//#define NETLINK_TEST 30
#define NETLINK_USER 31
//#define NETLINK_USER 0
#define MAX_PAYLOAD 1024

#define MSG_LEN 255
#define MAX_PLOAD 255

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    char  msg[MSG_LEN];
} user_msg_info;


/*
   struct sockaddr_nl src_addr, dest_addr;
   struct nlmsghdr *nlh = NULL;
   struct iovec iov;
   int netlink_socket;
   struct msghdr msg;
   */

int main(int argc, char *argv[])
{

    //int id = atoi(argv[1]);
    char type[10];
    strcpy(type,argv[2]);
    //printf("%d %s \n",id,type);

    char regis_request[50]="Registration. id=";
    strcat(regis_request,argv[1]);
    char part2[20]=", type=";
    strcat(part2,argv[2]);
    //printf("%s \n",part2);
    strcat(regis_request,part2);
    //printf("%s \n",regis_request);


    /*
    	struct sockaddr_nl src_addr, dest_addr;
    	struct nlmsghdr *nlh = NULL;
    	struct iovec iov;
    	int sock_fd;
    	struct msghdr msg;

    	memset(&msg,0,sizeof(msg));

    	sock_fd = socket(AF_NETLINK, SOCK_RAW,NETLINK_TEST);
    	memset(&src_addr, 0, sizeof(src_addr));
    	src_addr.nl_family = AF_NETLINK;
    	src_addr.nl_pid = getpid();
    	src_addr.nl_groups = 0;
    	bind(sock_fd, (struct sockaddr*)&src_addr,sizeof(src_addr));

    	memset(&dest_addr, 0, sizeof(dest_addr));
    	dest_addr.nl_family = AF_NETLINK;
    	dest_addr.nl_pid = 0;
    	dest_addr.nl_groups = 0;

    	nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    	nlh->nlmsg_pid = getpid();
    	nlh->nlmsg_flags = 0;
    	strcpy(NLMSG_DATA(nlh), regis_request);

    	iov.iov_base = (void *)nlh;
    	iov.iov_len = nlh->nlmsg_len;
    	msg.msg_name = (void *)&dest_addr;
    	msg.msg_namelen = sizeof(dest_addr);
    	msg.msg_iov = &iov;
    	msg.msg_iovlen = 1;

    	sendmsg(sock_fd, &msg, 0);

    	printf("Waiting for message from kernel\n");

    	// Read message from kernel
    	recvmsg(sock_fd, &msg, 0);

    	printf("Received message payload: %p\n",NLMSG_DATA(msg.msg_iov->iov_base));//%s
    	close(sock_fd);
    	*/

    int skfd;
    int ret;
    user_msg_info u_info;
    socklen_t len;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl saddr, daddr;
    char *umsg = regis_request;

    skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if(skfd == -1)
    {
        printf("create socket error\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = 100;  //(port ID)
    saddr.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        printf("bind() error\n");
        close(skfd);
        return -1;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel
    daddr.nl_groups = 0;

    //messsage
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = saddr.nl_pid; //self port
    memcpy(NLMSG_DATA(nlh), umsg, strlen(umsg));

    //sendto
    ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
    if(!ret)
    {
        printf("sendto error\n");
        close(skfd);
        exit(-1);
    }
    printf("send kernel: %s\n", umsg);

    //recvfrom
    memset(&u_info, 0, sizeof(u_info));
    len = sizeof(struct sockaddr_nl);
    ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len);
    if(!ret)
    {
        printf("recv form kernel error\n");
        close(skfd);
        exit(-1);
    }
    printf("from kernel: %s\n", u_info.msg);


    close(skfd);
    free((void *)nlh);

    return 0;

}
