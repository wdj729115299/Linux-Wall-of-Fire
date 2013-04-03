#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/timer.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/time.h>

static int bfw_start(void);
static void bfw_stop(void);
static int thread_fn();

static struct task_struct *thread1;

struct ipv4Node
{
	unsigned int ipAddress;
	unsigned long secs;
	struct ipv4Node *next;
};

typedef struct
{
	unsigned int start;
	unsigned int end;
	unsigned short protocol;
	unsigned short port;
	unsigned long sent;
	unsigned long received;
    struct ipv4Address *next;

} ipv4Address;

typedef struct
{
	ipv4Address *address;
	unsigned int count;
	unsigned int capacity;

} ipv4Addresses;

/* The white and blacklists */
static ipv4Addresses inWhite;
static ipv4Addresses inBlack;
static ipv4Addresses outBlack;

static struct ipv4Node *head;
static struct nf_hook_ops incomingIPv4;
static struct nf_hook_ops outgoingIPv4;

to leave firewall open */
static unsigned long elapsed = 60;

static unsigned int incomingIPv4Hook(unsigned int pf, struct sk_buff *buffer, 
									const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	unsigned short port = 0;
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct ipv4Node *cur;
	unsigned long secs = get_seconds();
	int firstByte,secByte,thirdByte,fourthByte = 0;
	int total = 0;

	/* make sure we have data, and valid device */
	if((buffer == NULL) || (in == NULL))
	{
		return NF_DROP;
	}

	/* Get the IP header from the buffer */
	iph = ip_hdr(buffer);

	/* Make sure we received the IP header information */
	if(iph == NULL)
	{
		return NF_DROP;
	}

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = (struct tcphdr*)((__u32*)iph + iph->ihl);
		if(tcph != NULL)
		{
			//port = tcph->dest;
			port = ((tcph->dest & 0xFF00) >> 8) | ((tcph->dest & 0x00FF) << 8);
		}
	}
	
	if(iph->protocol == IPPROTO_UDP)
	{
		udph = udp_hdr(buffer);
		if(udph != NULL)
		{
			port = udph->dest;
			//port = ((udph->dest & 0xFF00) >> 8) | ((udph->dest & 0x00FF) << 8);
		}
	}

	firstByte = iph->saddr & 0x000000FF;
	secByte = (iph->saddr & 0x0000FF00) >> 8;
	thirdByte = (iph->saddr & 0x00FF0000) >> 16;
	fourthByte = (iph->saddr & 0xFF000000) >> 24;
	total = (firstByte << 24) | (secByte << 16) | (thirdByte << 8) | fourthByte;
	
	if(total == 2130706433)
	{
		return NF_ACCEPT;
	}
	
	/* See if the source is in the adaptive list */
	cur = head;
	while(cur != NULL)
	{
		if(total == cur->ipAddress && ((secs - cur->secs) <= elapsed))
		{	
			printk(KERN_INFO "Packet received from:  %u.%u.%u.%u on port %u\n", iph->saddr & 0x000000FF,(iph->saddr & 0x0000FF00) >> 8,(iph->saddr & 0x00FF0000) >> 16,(iph->saddr & 0xFF000000) >> 24,port);
			return NF_ACCEPT;
		}
		cur = cur->next;
	}

	printk(KERN_INFO "Packet dropped from:  %u.%u.%u.%u on port %u\n", iph->saddr & 0x000000FF,(iph->saddr & 0x0000FF00) >> 8,(iph->saddr & 0x00FF0000) >> 16,(iph->saddr & 0xFF000000) >> 24,port);
	return NF_DROP;
}

static unsigned int outgoingIPv4Hook(unsigned int pf, struct sk_buff *buffer, 
									const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	unsigned int port = 0;
	struct iphdr *iph;
	struct ipv4Node *cur, *prev;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	bool add = true;
	int firstByte,secByte,thirdByte,fourthByte = 0;
	int total = 0;
	int i = 0;

	/* make sure we have data, and valid device */
	if((buffer == NULL) || (out == NULL))
	{
		return NF_DROP;
	}

	/* Get the IP header from the buffer */
	iph = ip_hdr(buffer);

	/* Make sure we received the IP header information */
	if(iph == NULL)
	{
		return NF_DROP;
	}
	
	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(buffer);
		if(tcph != NULL)
		{
			port = ((tcph->dest & 0xFF00) >> 8) | ((tcph->dest & 0x00FF) << 8);
		}
	}
	
	if(iph->protocol == IPPROTO_UDP)
	{
		udph = udp_hdr(buffer);
		if(udph != NULL)
		{
			port = ((udph->dest & 0xFF00) >> 8) | ((udph->dest & 0x00FF) << 8);
		}
	}

	firstByte = (iph->daddr & 0x000000FF);
	secByte = (iph->daddr & 0x0000FF00) >> 8;
	thirdByte = (iph->daddr & 0x00FF0000) >> 16;
	fourthByte = (iph->daddr & 0xFF000000) >> 24;
	total = (firstByte << 24) | (secByte << 16) | (thirdByte << 8) | fourthByte;

	/* Is the address blacklisted? */
	for(i = 0; i < outBlack.count; i++)
	{	
		if((total >= outBlack.address[i].start) && (total <= outBlack.address[i].end))
		{
			return NF_DROP;
		}
	}

	printk(KERN_INFO "Packet sent to:  %u.%u.%u.%u on port. %u\n", iph->daddr & 0x000000FF,(iph->daddr & 0x0000FF00) >> 8,(iph->daddr & 0x00FF0000) >> 16,(iph->daddr & 0xFF000000) >> 24,port);
	
	/* Check if outgoing IP needs to be added to list */
	prev = NULL;
	cur = head;
	while(cur != NULL)
	{
		if(cur->ipAddress == total)
		{
			cur->secs = get_seconds();
			add = false;

			if(cur != head)
			{
				prev->next = cur->next;
				cur->next = head;
				head = cur;
			}
			cur = NULL;
		}
		else
		{
			prev  = cur;
			cur = cur->next;
		}
	}
	
	/* Add the IP if it needed to be */
	if(add)
	{
		cur = NULL;
		cur = kmalloc(sizeof(struct ipv4Node), GFP_ATOMIC);
		if(cur != NULL)
		{
			cur->ipAddress =  total;
			cur->secs = get_seconds();
			cur->next = head;
			head = cur;
		}
	}
	return NF_ACCEPT;
}

static void init_lists(ipv4Addresses *list)
{
	list->count = 0;
	list->capacity = 0;
}

static int thread_fn()
{
	//unsigned long j0,j1;
	//int delay = 60*HZ;
	//j0 = jiffies;
	//j1 = j0 + delay;

	printk(KERN_INFO "In thread1\n");
	
	/*while(time_before(jiffies,j1))
	{
		printk(KERN_INFO "Looping\n");
		schedule();
	}*/

	//set_current_state(TASK_INTERRUPTIBLE);
	while(!kthread_should_stop())
	{
		printk(KERN_INFO "in kernel thread\n");
		/* delay functions are busy-waiting; other tasks can't be run during time lapse */
		//mdelay(200);
		msleep(5000);
	//	schedule();
	//	printk(KERN_INFO "Forever\n");
	//	set_current_state(TASK_INTERRUPTIBLE);
	}
	//set_current_state(TASK_RUNNING);

	return 0;
}

static int bfw_start()
{
	struct ipv4Node *cur;
	char name[8]="thread1";

	printk(KERN_INFO "Firewall initializing..\n");
	
	/* Start thread */
	printk(KERN_INFO "Starting thread...\n");
	thread1 = kthread_run(thread_fn,NULL,name);

	/*thread1 = kthread_create(thread_fn,NULL,our_thread);

	if(thread1)
	{
		printk(KERN_INFO "Attempting to start thread..\n");
		wake_up_process(thread1);
	}
	*/

	head = NULL;
	cur = kmalloc(sizeof(struct ipv4Node), GFP_ATOMIC);
	if(cur != NULL)
	{
		cur->ipAddress =  2130706433;
		cur->secs = get_seconds();
		cur->next = head;
		head = cur;
	}
	
	incomingIPv4.hook = (nf_hookfn *)incomingIPv4Hook;
	incomingIPv4.pf = PF_INET;
	incomingIPv4.hooknum = NF_INET_PRE_ROUTING;
	incomingIPv4.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&incomingIPv4);

	outgoingIPv4.hook = (nf_hookfn *)outgoingIPv4Hook;
	outgoingIPv4.pf = PF_INET;
	outgoingIPv4.hooknum = NF_INET_POST_ROUTING;
	outgoingIPv4.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&outgoingIPv4);
	
	/* Initialize white and black lists */
	init_lists(&inWhite);
	init_lists(&inBlack);
	init_lists(&outBlack);

	return 0;
}

static void bfw_stop() 
{
	struct ipv4Node *cur;
	printk(KERN_INFO "Firewall exiting..\n");
	
	/* Stop thread */
	kthread_stop(thread1);
	printk(KERN_INFO "Thread stopped..\n");

	/* Stop Capturing Packets */
	nf_unregister_hook(&incomingIPv4);
	nf_unregister_hook(&outgoingIPv4);
	
	while(head != NULL)
	{
		cur = head->next;
		kfree(head);
		head = cur;
	}
}

/* module_init == int main() */
module_init(bfw_start);

/* module_exit: where you will clean up things */
module_exit(bfw_stop);

/* define the license */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Barton F. Cone");
MODULE_DESCRIPTION("bfw: adaptive firewall");