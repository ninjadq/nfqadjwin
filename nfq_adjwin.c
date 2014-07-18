
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <limits.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#define bool int
#include <libnetfilter_queue/pktbuff.h>
#undef bool
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>

#include <linux/tcp.h>
#include <linux/ip.h>
#include <string.h>

int Total_traffic = 400000; /* The total traffic which passed to the device, default is 4Mbps */

int 
Get_tcp_num();

int
Get_current_traffic();

__u16 
Get_fixed_winsize(int);

static int 
cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
    
	char buf[4096] __attribute__ ((aligned));

    if( argc == 2 ) Total_traffic = atoi(argv[1]); /* get the user specific total traffic value */

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
    /* insert fixed value here */
	qh = nfq_create_queue(h,  0, &cb, (void*)NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

    /*obtain the file descripter*/
	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}


__u16 Get_fixed_winsize(int total_traffic)
{
  /*return the fixed windowsize based on the current tcps*/
  __u16 winSize;
  int tcpn, ct, raw_datar;
  tcpn = Get_tcp_num();
  ct = Get_current_traffic();
  raw_datar = (total_traffic - ct)/tcpn;
  winSize = raw_datar / 30000;
  
  return 200;
}


int Get_current_traffic()
{
  return 300;
}

int Get_tcp_num()
{
  /* Get the number of all current tcps*/
  FILE * stream;
  char buf[1024];
  int tcpnum;
  
  bzero(buf, sizeof(buf));
  /*Using linux commend line to get tcps number*/
  stream = popen("netstat -nat | wc -l", "r");
  fread(buf, sizeof(char), sizeof(buf), stream);
  /*the return value is type in but fread is returned string*/
  tcpnum = atoi(buf);

  /*close the pipeline*/
  pclose(stream);

  return tcpnum;
}


/*callback, all modification on packet are on this function*/
static int cb(
	      struct nfq_q_handle *qh,    /* The queue hable returened by nfq_create_queue */
	      struct nfgenmsg *nfmsg,     /* message object that contains the packet */
	      struct nfq_data *nfa,       /* Netlink packet data handle*/
	      void *data                  /* The valued passed to the data parameter of nfq_create_queue */
	      )
{
  char buf[PATH_MAX] __attribute__ ((aligned));
  
  u_int32_t id = 0;
  struct nfqnl_msg_packet_hdr *ph;

  unsigned char *pdata;
  int packet_len;
  
  struct pkt_buff *pkt;
  struct tcphdr *tcph;
  struct iphdr *iph;

  /* default value is 200*/
  __u16 winSize = Get_fixed_winsize(Total_traffic);
  /*printf ("%d\n", winSize);*/
  
  /*get header of data*/
  ph = nfq_get_msg_packet_hdr(nfa);
  if(ph){
    id = ntohl(ph->packet_id);
  }
  /* pdata point to the payload of packet i.e. the data of packet*/
  packet_len = nfq_get_payload(nfa, &pdata);
  /*
    alloc a space to save the copied data then copy the data to it
  */
  pkt = pktb_alloc(AF_INET, pdata, packet_len, 0);
  iph = nfq_ip_get_hdr(pkt);
  nfq_ip_set_transport_header(pkt, iph);
  tcph = nfq_tcp_get_hdr(pkt);

  if(tcph){
    /* nfq_ip_snprintf(buf, PATH_MAX, iph); */
    /* printf("IP: %s\n", buf); */
    tcph->window = winSize;/* type is __u16*/

    /*Header is changed so we need to recompute the checksum*/
    nfq_ip_set_checksum(iph);
    nfq_tcp_compute_checksum_ipv4(tcph, iph);
    /*copy the new checksum to the apropriate position*/
    memcpy(pdata, pktb_data(pkt), packet_len);
    
    nfq_tcp_snprintf(buf, PATH_MAX, tcph);
    printf("TCP: %s\n", buf);
  } else {
    printf("%s\n", "NOT TCP");
  }
  
  pktb_free(pkt);
  return nfq_set_verdict(qh, id, NF_ACCEPT, packet_len, pdata);
}
