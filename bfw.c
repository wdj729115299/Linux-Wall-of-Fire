#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/timer.h>

#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/time.h>

static int bfw_start(void);
static void bfw_stop(void);
//static int thread_fn();
static int is_number(char c);
static void print_white(void);
static void print_in_black(void);
static void print_out_black(void);
static void destroy_white(void);
static void destroy_in_black(void);
static void destroy_out_black(void);
static struct task_struct *thread1;
static int read_file(char *fileName, int flag);
static void parse_data(char *data, int size, int numLines, int flag);
static unsigned int big_endian(int fsByte, int sByte, int tByte, int ftByte);
static void init_white(unsigned int ip, unsigned short protocol, unsigned short port);
static void init_in_black(unsigned int ip, unsigned short protocol, unsigned short port);
static void init_out_black(unsigned int ip, unsigned short protocol, unsigned short port);

//static DEFINE_SPINLOCK(my_lock);

struct ipv4Node
{
	unsigned int ipAddress;
	unsigned long sent;
	unsigned long recv;
	unsigned long secs;
	struct ipv4Node *next;
};

struct ipv4Address
{
	unsigned int start;
	unsigned int end;
	unsigned short protocol;
	unsigned short port;
	unsigned long sent;
	unsigned long received;
	struct ipv4Address *next;
};

/* The white and blacklists */
static struct ipv4Address *inWhiteHead;
static struct ipv4Address *inBlackHead;
static struct ipv4Address *outBlack;
static struct ipv4Node *head;
static struct nf_hook_ops incomingIPv4;
static struct nf_hook_ops outgoingIPv4;

/* Amount of time to leave firewall open */
static unsigned long elapsed = 60;

/* White and blacklist files */
static char* wFile = "/home/bcone/Documents/Firewall/FileTest/in.white";
static char* bFileIn = "/home/bcone/Documents/Firewall/FileTest/in.black";
static char* bFileOut = "/home/bcone/Documents/Firewall/FileTest/out.black";

static unsigned int incomingIPv4Hook(unsigned int pf, struct sk_buff *buffer, 
									const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	int firstByte,secByte,thirdByte,fourthByte = 0;
	unsigned long secs = get_seconds();
	unsigned short port = 0;
	unsigned long rec = 0;
	//unsigned long flags;
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct ipv4Node *cur;
	struct ipv4Address *wCur;
	int total = 0;
	int valid = 0;

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
			port = ((tcph->dest & 0xFF00) >> 8) | ((tcph->dest & 0x00FF) << 8);
		}
	}
	
	if(iph->protocol == IPPROTO_UDP)
	{
		udph = udp_hdr(buffer);
		if(udph != NULL)
		{
			port = udph->dest;
		}
	}

	firstByte = iph->saddr & 0x000000FF;
	secByte = (iph->saddr & 0x0000FF00) >> 8;
	thirdByte = (iph->saddr & 0x00FF0000) >> 16;
	fourthByte = (iph->saddr & 0xFF000000) >> 24;
	total = (firstByte << 24) | (secByte << 16) | (thirdByte << 8) | fourthByte;

	/* Scan whitelist (allows for multiple entrys) */
	//spin_lock_irqsave(&my_lock,flags);
	wCur = inWhiteHead;
	while(wCur != NULL)
	{
		if((wCur->start >=  total) && (wCur->end <= total))
		{
			if((wCur->protocol == 0) && (wCur->port == 0)) {
				rec = wCur->received++;
				return NF_ACCEPT;
			}
			if(wCur->protocol != 0 || wCur->port != 0)
			{	
				if((wCur->protocol != 0) && (wCur->protocol == iph->protocol))
				{
					if((wCur->port != 0) && (wCur->port == port))
					{
						rec = wCur->received++;
						valid = 1;
					}
					else if(wCur->port == 0)
					{
						rec = wCur->received++;
						valid = 1;
					}
				}
			}
		}
		wCur = wCur->next;
	}

	if(valid) 
	{
		printk(KERN_INFO "Whitelist packet received from: %u.%u.%u.%u:%u received: %lu\n", iph->saddr & 0x000000FF,(iph->saddr & 0x0000FF00) >> 8,(iph->saddr & 0x00FF0000) >> 16,(iph->saddr & 0xFF000000) >> 24,port,rec);
		return NF_ACCEPT;
	}
	
	valid = 0;
	wCur = NULL;

	/* Scan blacklist */
	wCur = inBlackHead;
	while(wCur != NULL)
	{
		if((wCur->start >=  total) && (wCur->end <= total))
		{
			if((wCur->protocol == 0) && (wCur->port == 0)) {
				rec = wCur->received++;
				return NF_DROP;
			}
			if(wCur->protocol != 0 || wCur->port != 0)
			{	
				if((wCur->protocol != 0) && (wCur->protocol == iph->protocol))
				{
					if((wCur->port != 0) && (wCur->port == port))
					{
						rec = wCur->received++;
						valid = 1;
					}
					else if(wCur->port == 0)
					{
						rec =wCur->received++;
						valid = 1;
					}
				}
			}
		}
		wCur = wCur->next;
	}
	
	if(valid)
	{
		printk(KERN_INFO "Blacklist packet received from: %u.%u.%u.%u:%u Received: %lu", iph->saddr & 0x000000FF,(iph->saddr & 0x0000FF00) >> 8,(iph->saddr & 0x00FF0000) >> 16,(iph->saddr & 0xFF000000) >> 24,port,rec);
		return NF_DROP;
	}
	//spin_lock_irqsave(&my_lock,flags);
	/* See if the source is in the adaptive list */
	cur = head;
	while(cur != NULL)
	{
		if(total == cur->ipAddress && ((secs - cur->secs) <= elapsed))
		{	
			cur->recv++;
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
	unsigned long secs = get_seconds();
	unsigned long sent = 0;
	//unsigned long flags;
	struct iphdr *iph;
	struct ipv4Node *cur, *prev;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct ipv4Address *wCur;
	bool add = true;
	int firstByte,secByte,thirdByte,fourthByte = 0;
	int total = 0;
	int valid = 0;
	
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
	
	/* Is the address blacklisted? (supports multiple entries) */
	//spin_lock_irqsave(&my_lock,flags);
	wCur = outBlack;
	while(wCur != NULL)
	{
		if((wCur->start >=  total) && (wCur->end <= total))
		{
			if((wCur->protocol == 0) && (wCur->port == 0)) {
				sent = wCur->sent++;
				return NF_DROP;
			}
			if(wCur->protocol != 0 || wCur->port != 0)
			{	
				if((wCur->protocol != 0) && (wCur->protocol == iph->protocol))
				{
					if((wCur->port != 0) && (wCur->port == port))
					{
						sent = wCur->sent++;
						valid = 1;
					}
					else if(wCur->port == 0)
					{
						sent = wCur->sent++;
						valid = 1;
					}
				}
			}
		}
		wCur = wCur->next;
	}
	
	if(valid)
	{
		printk(KERN_INFO "Blacklist attempt to: %u.%u.%u.%u:%u Sent: %lu\n", iph->daddr & 0x000000FF,(iph->daddr & 0x0000FF00) >> 8,(iph->daddr & 0x00FF0000) >> 16,(iph->daddr & 0xFF000000) >> 24,port,sent);

		return NF_DROP;
	}
	//spin_unlock_irqrestore(&my_lock,flags);

	printk(KERN_INFO "Packet sent to:  %u.%u.%u.%u on port. %u\n", iph->daddr & 0x000000FF,(iph->daddr & 0x0000FF00) >> 8,(iph->daddr & 0x00FF0000) >> 16,(iph->daddr & 0xFF000000) >> 24,port);
	
	/* Check if outgoing IP needs to be added to list */
	prev = NULL;
	cur = head;
	while(cur != NULL)
	{
		if(cur->ipAddress == total)
		{
			cur->secs = get_seconds();
			cur->sent++;
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
			cur->sent = 1;
			cur->recv = 0;
			cur->next = head;
			head = cur;
		}
	}
	
	/* clean up list */
	prev = NULL;
	cur = NULL;
	cur = head;
	while(cur != NULL)
	{	
		if((secs - cur->secs) > elapsed)
		{	
			if(cur->next == NULL)
			{
				prev->next = cur->next;
				kfree(cur);
				break;
			}
			else if(cur != head)
			{
				prev->next = cur->next;
				kfree(cur);
				cur = prev->next;
			}
			else
			{
				head = cur->next;
				kfree(cur);
			}
		}
		prev = cur;
		cur = cur->next;
	}
	cur = NULL;

	return NF_ACCEPT;
}

/*static int thread_fn()
{
	unsigned long flags;

	while(!kthread_should_stop())
	{
		spin_lock_irqsave(&my_lock,flags);
			destroy_white();
			printk(KERN_INFO "Parsing in.white");
			read_file(wFile, 0);
			//print_white();

			destroy_in_black();
			printk(KERN_INFO "\nParsing in.black");
			read_file(bFileIn, 1);
			//print_in_black();
			
			destroy_out_black();
			printk(KERN_INFO "\nParsing out.black");
			read_file(bFileOut, 2);
			//print_out_black();
		spin_unlock_irqrestore(&my_lock,flags);
		msleep(60000);
	}

	return 0;
}
*/

/* Read input files */
int read_file(char *fileName, int flag)
{	
	unsigned long long size = 0;
	struct file* filp = NULL;
	mm_segment_t oldfs;
	int ret;
	int err = 0;
	char *data = NULL;
	int i = 0;
	int numLines = 0;

	oldfs = get_fs();
	set_fs(get_ds());
	
	filp = filp_open(fileName,O_RDONLY,0);
	
	set_fs(oldfs);
	
	if(IS_ERR(filp))
	{
		err = PTR_ERR(filp);
		return 0;
	}
	else
	{
		set_fs(get_ds());
		
		size = filp->f_dentry->d_inode->i_size;
		data = kmalloc(sizeof(char)*size,GFP_ATOMIC);
		ret = vfs_read(filp,data,size,&filp->f_pos);
		set_fs(oldfs);
	}

	filp_close(filp, NULL);
	
	for(i; i < size; i++)
	{
		if(data[i] == '\n'){ numLines++; }
	}
	
	parse_data(data,size,numLines,flag);
	kfree(data);

	return ret;
}

/* Is this char a number? */
static int is_number(char c)
{
	int isNum = ((int)c) - 48;
	if(isNum >= 0 && isNum <=9) return 1;
	return 0;
}

/* Convert IP to big endian */
static unsigned int big_endian(int fsByte, int sByte, int tByte, int ftByte)
{
	return (fsByte << 24) | (sByte << 16) | 
			 (tByte << 8) | ftByte;
}

/* Parse the data read in from the file (need to break this up) */
static void parse_data(char *data, int size, int numLines, int flag)
{
	int fsByte = 0;
	int sByte = 0;
	int tByte = 0;
	int ftByte = 0;
	int i = 0;
	int linesParsed = 0;
	int offset = 0;
	int cidr = 0;
	unsigned int isNum = 0;
	unsigned int count = 0;
	unsigned int protocol = 0;
	unsigned int port = 0;
	unsigned int ipTotal = 0;
	
	while(linesParsed != (numLines-1)) {
	
		/* Parse IP */
		for(i; i < size; i++)
		{
			isNum = ((int)data[i]) - 48;
			
			if(isNum >= 0 && isNum <=9)
			{
				if(count == 0) {
					fsByte = isNum + fsByte;
					if(data[i+1] != '.') fsByte = fsByte * 10;
				}
				if(count == 1) {
					sByte = isNum + sByte;
					if(data[i+1] != '.') sByte = sByte * 10;
				}
				if(count == 2) {
					tByte = isNum + tByte;
					if(data[i+1] != '.') tByte = tByte * 10;
				}
				if(count == 3) {
					ftByte = isNum + ftByte;
					if(data[i+1] != '/') ftByte = ftByte * 10;
				}
			}
			if(data[i+1] == '.') count++;
			if(data[i+1] == '/'){ offset = i+2; break; } 
		}
		
		/* Offset currently first pos of CIDR */
		ipTotal = big_endian(fsByte,sByte,tByte,ftByte);

		/* Get CIDR notation */
		i = offset;
		for(i; i < size; i++)
		{	
			if(data[i+1] == ' ' || data[i+1] == '\n') {
				cidr = ((int)data[i]) - 48;
				if(data[i+1] == '\n') linesParsed++;
				offset = i+1; /* Offset is char following cidr of 1 digits */
				break;
			}
			else
			{
				cidr = ((((int)data[i]) - 48) * 10) + ((int)data[i+1]) - 48;
				if(data[i+2] == '\n') linesParsed++;
				offset = i+2; /* Offset is char following cidr of 2 digits */
				break;
			}
		}
		
		/* Grab layer3 protocol (icmp,tcp,udp) */
		i = offset;
		if(data[i] == ' ') {
			i++; /* put *offset* at first char of protocol */
			isNum = ((int)data[i]) - 48;
			if(isNum >= 0 && isNum <= 9) {
				if(is_number(data[i+1])) {
					//printk(KERN_INFO "Layer 3: UDP\n");
					protocol = 17;
					if(data[i+2] == '\n') linesParsed++;
					offset = i+2;/* Offset is char following protocol */
				}
				else if(isNum == 6) {
					//printk(KERN_INFO "Layer 3: TCP\n");
					protocol = 6;
					if(data[i+1] == '\n') linesParsed++;
					offset = i + 1;
				}
				else if(isNum == 1) {
					//printk(KERN_INFO "Layer 3: ICMP\n");
					protocol = 1;
					if(data[i+1] == '\n') linesParsed++;
					offset = i + 1;
				}
			}
			else
			{	/* Make sure you start with smallest */
				if(strncmp("TCP",data+i,3) == 0) {
					//printk(KERN_INFO "Layer 3: TCP\n");
					protocol = 6;
					if(data[i+3] == '\n') linesParsed++;
					offset = i + 3;
				}
				else if(strncmp("tcp",data+i,3) == 0) {
					//printk(KERN_INFO "Layer 3: tcp\n");
					protocol = 6;
					if(data[i+3] == '\n') linesParsed++;
					offset = i + 3;
				}
				else if(strncmp("UDP",data+i,3) == 0) {
					//printk(KERN_INFO "Layer 3: UDP\n");
					protocol = 17;
					if(data[i+3] == '\n') linesParsed++;
					offset  = i + 3;
				}
				else if(strncmp("udp",data+i,3) == 0) {
					//printk(KERN_INFO "Layer 3: udp\n");
					protocol = 17;
					if(data[i+3] == '\n') linesParsed++;
					offset = i + 3;
				}
				else if(strncmp("ICMP",data+i,4) == 0) {
					//printk(KERN_INFO "Layer 3: ICMP\n");
					protocol = 1;
					if(data[i+4] == '\n') linesParsed++;
					offset = i + 4;
				}
				else if(strncmp("icmp",data+i,4) == 0) {
					//printk(KERN_INFO "Layer 3: icmp\n");
					protocol = 1;
					if(data[i+4] == '\n') linesParsed++;
					offset = i + 4;
				}
			}
		}
		
		/* Grab port */
		i = offset;
		if(data[i] == ' ')
		{
			i++; /* Move offset to first char of port */
			if(is_number(data[i])) {
				for(i; i < size; i++) {
					isNum = ((int)data[i]) - 48;
					if(isNum >= 0 && isNum <= 9)
					{
						port = isNum + port;
						if(data[i+1] != '\n') port = port * 10;
					}
					if(data[i+1] == '\n') { 
						offset = i+1; 
						linesParsed++;  
						break; 
					}
				}
			}
			else
			{
				if(strncmp("SSH",data+i,3) == 0) {
					//printk(KERN_INFO "Layer 7: SSH\n");
					port = 22;
					if(data[i+3] == '\n') linesParsed++;
					offset = i + 3;
				}
				else if(strncmp("ssh",data+i,3) == 0) {
					//printk(KERN_INFO "Layer 7: ssh\n");
					port = 22;
					if(data[i+3] == '\n') linesParsed++;
					offset = i + 3;
				}
				else if(strncmp("DNS",data+i,3) == 0) {
					//printk(KERN_INFO "Layer 7: DNS\n");
					port = 53;
					if(data[i+3] == '\n') linesParsed++;
					offset = i + 3;
				}
				else if(strncmp("dns",data+i,3) == 0) {
					//printk(KERN_INFO "Layer 7: dns\n");
					port = 53;
					if(data[i+3] == '\n') linesParsed++;
					offset = i + 3;
				}
			}
		}

		if(flag == 0) {
			init_white(ipTotal,protocol,port);
		}
		else if(flag == 1) {
			init_in_black(ipTotal,protocol,port);
		}
		else if(flag == 2) {
			init_out_black(ipTotal,protocol,port);
		}

		/* Move offset to first char of next line */
		offset = i++;

		/* Clean up values for next lines */
		fsByte = 0;
		sByte = 0;
		tByte = 0;
		ftByte = 0;
		count = 0;
		cidr = 0;
		protocol = 0;
		port = 0;
		ipTotal = 0;
	}
}

/* Print outgoing blacklist */
static void print_out_black()
{
	struct ipv4Address *cur;

	cur = outBlack;
	while(cur != NULL)
	{
		printk(KERN_INFO "IP: %u Protocol: %u Port %u",cur->start,cur->protocol,cur->port);
		cur = cur->next;
	}

}

/* Print incoming blacklist */
static void print_in_black()
{
	struct ipv4Address *cur;

	cur = inBlackHead;
	while(cur != NULL)
	{
		printk(KERN_INFO "IP: %u Protocol: %u Port %u",cur->start,cur->protocol,cur->port);
		cur = cur->next;
	}
}

/* Print whitelist */
static void print_white()
{
	struct ipv4Address *cur;
	
	cur = inWhiteHead;
	while(cur != NULL)
	{
		printk(KERN_INFO "IP: %u Protocol: %u Port: %u",cur->start,cur->protocol,cur->port);
		cur = cur->next;
	}
}

/* Free outgoing blacklist memory */
static void destroy_out_black()
{
	struct ipv4Address *cur;
	
	while(outBlack != NULL)
	{
		cur = outBlack->next;
		kfree(outBlack);
		outBlack = cur;
	}
}

/* Free incoming blacklist memory */
static void destroy_in_black()
{
	struct ipv4Address *cur;

	while(inBlackHead != NULL)
	{
		cur = inBlackHead->next;
		kfree(inBlackHead);
		inBlackHead = cur;
	}
}

/* Free whitelist memory */
static void destroy_white()
{
	struct ipv4Address *cur;

	while(inWhiteHead != NULL)
	{
		cur = inWhiteHead->next;
		kfree(inWhiteHead);
		inWhiteHead = cur;
	}
}

/* Create outgoing blacklist */
static void init_out_black(unsigned int ip, unsigned short protocol, unsigned short port)
{
	struct ipv4Address *cur;

	cur = NULL;
	cur = kmalloc(sizeof(struct ipv4Address), GFP_ATOMIC);
	if(cur != NULL)
	{
		cur->start = ip;
		cur->end = ip;
		cur->protocol = protocol;
		cur->port = port;
		cur->sent = 0;
		cur->received = 0;
		cur->next = outBlack;
		outBlack = cur;
	}
}

/* Create incoming blacklist */
static void init_in_black(unsigned int ip, unsigned short protocol, unsigned short port)
{
	struct ipv4Address *cur;

	cur = NULL;
	cur = kmalloc(sizeof(struct ipv4Address), GFP_ATOMIC);
	if(cur != NULL)
	{
		cur->start = ip;
		cur->end = ip;
		cur->protocol = protocol;
		cur->port = port;
		cur->sent = 0;
		cur->received = 0;
		cur->next = inBlackHead;
		inBlackHead = cur;
	}
}

/* Create whitelist */
static void init_white(unsigned int ip, unsigned short protocol, unsigned short port)
{
	struct ipv4Address *cur;

	cur = NULL;
	cur = kmalloc(sizeof(struct ipv4Address), GFP_ATOMIC);
	if(cur != NULL) 
	{
		cur->start = ip;
		cur->end = ip;
		cur->protocol = protocol;
		cur->port = port;
		cur->sent = 0;
		cur->received = 0;
		cur->next = inWhiteHead;
		inWhiteHead = cur;
	}
}

static int bfw_start()
{
	struct ipv4Node *cur;
	char name[8]="thread1";
	
	printk(KERN_INFO "Firewall initializing..\n");
	inWhiteHead = NULL;
	
	read_file(wFile, 0);
	read_file(bFileIn, 1);
	read_file(bFileOut, 2);

	/* Start thread */
	//printk(KERN_INFO "Starting thread...\n");
	//thread1 = kthread_run(thread_fn,NULL,name);

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
	
	return 0;
}

static void bfw_stop() 
{
	struct ipv4Node *cur;

	printk(KERN_INFO "Firewall exiting..\n");
	
	/* Stop thread */
	//kthread_stop(thread1);
	//printk(KERN_INFO "Thread stopped..\n");

	/* Stop Capturing Packets */
	nf_unregister_hook(&incomingIPv4);
	nf_unregister_hook(&outgoingIPv4);
	
	/* Free adaptive list */
	while(head != NULL)
	{
		cur = head->next;
		kfree(head);
		head = cur;
	}
	
	destroy_white();
	destroy_in_black();
	destroy_out_black();
}

/* module_init == int main() */
module_init(bfw_start);

/* module_exit: where you will clean up things */
module_exit(bfw_stop);

/* define the license */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Barton F. Cone");
MODULE_DESCRIPTION("bfw: adaptive firewall");
