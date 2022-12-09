
LOADER_PROG_HEAD='''
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

#define ARRAY_MAP_SIZE 0x1337

int create_map();
int create_map(){

        union bpf_attr map_attrs =
        {
                .map_type = BPF_MAP_TYPE_ARRAY,
                .key_size = 4,
                .value_size = ARRAY_MAP_SIZE,
                .max_entries = 1,
        };

        int ret = -1;

        long p[3] = {BPF_MAP_CREATE, (long)&map_attrs,sizeof(map_attrs)};
        ret = lkl_syscall(__lkl__NR_bpf, p);

        return ret;
}

int main(void)
{
	/* Start the kernel */
	lkl_start_kernel(&lkl_host_ops, "mem=100M");


        int store_map_fd = 0 ;
        store_map_fd = create_map();

	/*Simple Valid Program*/
	struct bpf_insn prog_valid[] = {
'''
#		BPF_MOV64_IMM(BPF_REG_0, 0),          // R0 = 0
#		BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 2), // R0 = R0 + 2
#		BPF_MOV32_IMM(BPF_REG_0, 2),          // R0 = 2
#		BPF_EXIT_INSN()                       // exit()

LOADER_PROG_TAIL='''
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


LOADER_PROG_MAP_LOOKUP = '''
		// Call helper function map_lookup_elem. First parameter is in R1 // (map pointer).
		BPF_MOV64_IMM(BPF_REG_0, 0),  // R0 = 0
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10 ),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
		BPF_LD_MAP_FD(BPF_REG_1, store_map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
		BPF_EXIT_INSN(),
		/* store the map value pointer into designated register */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),

		/*REG_4 with a tnum mask of 0xFFFFFFFFFFFFFFFF */ \
		BPF_MOV64_REG(BPF_REG_4, BPF_REG_7),
                /*Initialize the registers*/
		BPF_MOV32_IMM(BPF_REG_5, 0),
		BPF_MOV32_IMM(BPF_REG_6, 0),
		BPF_MOV32_IMM(BPF_REG_7, 0),
		BPF_MOV32_IMM(BPF_REG_8, 0),
		BPF_MOV32_IMM(BPF_REG_9, 0),


'''
