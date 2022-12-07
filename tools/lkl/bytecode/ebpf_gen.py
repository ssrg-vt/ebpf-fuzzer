import random
import pprint
import subprocess

import sys

from eBPFGenerator import eBPFGenerator


PRINT_DEBUG=0

STR_HEAD='''
#include <errno.h>
#include <string.h>
#include <linux/filter.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <lkl.h>
#include <lkl_host.h>

#include <sys/time.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../tests/test.h"
#include "bpf.h"


#define NUM_ICMP 10
#define ARRAY_MAP_SIZE 0x1337

char bpf_log_buf[BPF_LOG_BUF_SIZE];

static u_short in_cksum(const u_short *addr, register int len, u_short csum)
{
        int nleft = len;
        const u_short *w = addr;
        u_short answer;
        int sum = csum;

        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        if (nleft == 1)
                sum += htons(*(u_char *)w << 8);

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return answer;
}

int lkl_test_icmp(int prog_fd)
{
	int sock, ret, i;
	struct lkl_iphdr *iph;
	struct lkl_icmphdr *icmp;
	struct lkl_sockaddr_in saddr;
	struct lkl_pollfd pfd;
	char buf[32];


	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	inet_aton("127.0.0.1",(struct in_addr *)&saddr.sin_addr.lkl_s_addr);

	printf("pinging %s\\n",
		      inet_ntoa(*(struct in_addr *)&saddr.sin_addr));

	sock = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_RAW, LKL_IPPROTO_ICMP);
	if (sock < 0) {
		printf("socket error (%s)\\n", lkl_strerror(sock));
		return TEST_FAILURE;
	}
#if 1
	if (lkl_sys_setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, (char *)&prog_fd, sizeof(prog_fd)) < 1) {
		printf("ATTACH BPF setsockopt %d\\n", errno);
	}
#endif 

	for (i = 0; i < NUM_ICMP; i++) {
		icmp = malloc(sizeof(struct lkl_icmphdr *));
		icmp->type = LKL_ICMP_ECHO;
		icmp->code = 0;
		icmp->checksum = 0;
		icmp->un.echo.sequence = htons(i);
		icmp->un.echo.id = 0;
		icmp->checksum = in_cksum((u_short *)icmp, sizeof(*icmp), 0);

		ret = lkl_sys_sendto(sock, icmp, sizeof(*icmp), 0,
				     (struct lkl_sockaddr *)&saddr,
				     sizeof(saddr));
		if (ret < 0) {
			printf("sendto error (%s)\\n", lkl_strerror(ret));
			return TEST_FAILURE;
		}

		free(icmp);

		pfd.fd = sock;
		pfd.events = LKL_POLLIN;
		pfd.revents = 0;

		ret = lkl_sys_poll(&pfd, 1, 1000);
		if (ret < 0) {
			printf("poll error (%s)\\n", lkl_strerror(ret));
			return TEST_FAILURE;
		}

		ret = lkl_sys_recv(sock, buf, sizeof(buf), LKL_MSG_DONTWAIT);
		if (ret < 0) {
			printf("recv error (%s)\\n", lkl_strerror(ret));
			return TEST_FAILURE;
		}

		iph = (struct lkl_iphdr *)buf;
		icmp = (struct lkl_icmphdr *)(buf + iph->ihl * 4);
		/* DHCP server may issue an ICMP echo request to a dhcp client */
		if ((icmp->type != LKL_ICMP_ECHOREPLY || icmp->code != 0) &&
		    (icmp->type != LKL_ICMP_ECHO)) {
			printf("no ICMP echo reply (type=%d, code=%d)\\n",
				      icmp->type, icmp->code);
			return TEST_FAILURE;
		}
		printf("ICMP echo reply (seq=%d)\\n", ntohs(icmp->un.echo.sequence));

	}

	return TEST_SUCCESS;
}

int main(void)
{
	/* Start the kernel */
	lkl_start_kernel(&lkl_host_ops, "mem=100M");

	/*Simple Valid Program*/
	struct bpf_insn prog_valid[] = {
'''
#		BPF_MOV64_IMM(BPF_REG_0, 0),          // R0 = 0
#		BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 2), // R0 = R0 + 2
#		BPF_MOV32_IMM(BPF_REG_0, 2),          // R0 = 2
#		BPF_EXIT_INSN()                       // exit()

STR_TAIL='''
	};

	int insn_cnt = sizeof(prog_valid) / sizeof(struct bpf_insn);
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
		.insns     = ptr_to_u64(prog_valid),
		.insn_cnt  = insn_cnt,
		.license   = ptr_to_u64("GPL"),
		.log_buf   = ptr_to_u64(bpf_log_buf),
		.log_size  = BPF_LOG_BUF_SIZE,
		.log_level = 2, /*2 - detailed register states , 1 - minimum logs*/
		.kern_version = LINUX_VERSION_CODE
	};

	/*Load the BPF program, invokes the verifier*/
	int prog_fd;
	long p[3] = {BPF_PROG_LOAD, (long)&attr,sizeof(attr)};
	prog_fd = lkl_syscall(__lkl__NR_bpf, p); 

	if(prog_fd < 0){
		printf("BPF Verification Failed\\n");
	        printf("===== verifier o/p: begin =====\\n %s\\n============ end ============= \\n",bpf_log_buf);
		return 0;
	} else {
		printf("BPF Verification Passed\\n");
	}



	/* Attach to socket to run the ebpf program on receiving packet */
	int sock,ret;
	sock = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_STREAM, 0);

	struct lkl_ifreq ifr;
	strcpy(ifr.lkl_ifr_name, "lo");

	ret = lkl_sys_ioctl(sock, LKL_SIOCGIFINDEX, (long)&ifr);
	lkl_if_up(1); // BACKEND_NONE
	lkl_test_icmp(prog_fd);

	sleep(1);

	return 0;
}
'''

'''
struct bpf_insn {
        __u8    code;           /* opcode */
        __u8    dst_reg:4;      /* dest register */
        __u8    src_reg:4;      /* source register */
        __s16   off;            /* signed offset */
        __s32   imm;            /* signed immediate constant */
};"		
'''


'''

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                         \
614         ((struct bpf_insn) {                                    \
615                 .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,     \
616                 .dst_reg = DST,                                 \
617                 .src_reg = 0,                                   \
618                 .off   = OFF,                                   \
619                 .imm   = IMM })

577 #define BPF_STX_MEM(SIZE, DST, SRC, OFF)                        \
578         ((struct bpf_insn) {                                    \
579                 .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,    \
580                 .dst_reg = DST,                                 \
581                 .src_reg = SRC,                                 \
582                 .off   = OFF,                                   \
583                 .imm   = 0 })
584


ST -> rand(IMM), src_reg = 0
STx -> ran(REG) , imm = 0
'''

def random_bpf_insn_all_class():

    random_insn_list = []

    random_insn_list = gen_alu_insn(random_insn_list)
    random_insn_list = gen_mov_insn(random_insn_list)
    random_insn_list = gen_ld_insn(random_insn_list) 
    random_insn_list = gen_st_insn(random_insn_list)
    random_insn_list = gen_jmp_insn(random_insn_list)
    random_insn_list = gen_exit_insn(random_insn_list)

    random_insn_list = fix_unintialized(random_insn_list) 
    if PRINT_DEBUG:
        pprint.pprint(random_insn_list)
     
    return print_bpf_insn_to_str(random_insn_list)


def check_verification_status(out):

    for line in out:
        if "BPF Verification Failed" in line:
            return False
    return True



# Main
##########################################################
##########################################################

use_last_code = False
if len(sys.argv) == 2:
    if sys.argv[1] ==  "--use-last":
        use_last_code = True;


ebpf_gen = eBPFGenerator()

if not use_last_code:    
    #random_str = random_bpf_insn_all_class() 
    random_str = ebpf_gen.generate_instructions(random.randint(2,200) )#to do max_size 
    c_contents  = STR_HEAD + random_str + STR_TAIL

    f = open("out.c","w")
    f.write(c_contents)
    f.close()

if PRINT_DEBUG:
    for i  in range(0,11):
        print("reg_" + str(i) + " " + str(reg_init[i]))

# Compile Loader Program 
build_cmd = "bash ./build.sh out"
build_out = subprocess.run(build_cmd.split(' '))

# Execute 
exec_cmd = "./out"
ebpf_out = subprocess.run(exec_cmd.split(' '),stdout=subprocess.PIPE)

ebpf_out = ebpf_out.stdout.decode("utf-8")

if(check_verification_status(ebpf_out)):
    print("Verification Passed")
else:
    print("Verification Failed")
    print(random_str)

if not use_last_code:    
    print(random_str)
