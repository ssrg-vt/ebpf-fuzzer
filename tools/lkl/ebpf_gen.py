import random
import pprint
import subprocess

import sys



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

reg_init = [None] * 11

BPF_EXIT = 0x90


BPF_W =  0x00    # word
BPF_H =  0x08    # half word
BPF_B =  0x10    # byte 
BPF_DW = 0x18

BPF_IMM =  0x00  # used for 32-bit mov in classic BPF and 64-bit in eBPF 
BPF_ABS =  0x20
BPF_IND =  0x40
BPF_MEM =  0x60
BPF_LEN =  0x80  # classic BPF only, reserved in eBPF
BPF_MSH =  0xa0  # classic BPF only, reserved in eBPF 
BPF_XADD =  0xc0  # eBPF only, exclusive add 

BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

BPF_INSN_CLASS = [ BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_JMP32, BPF_ALU64 ]
BPF_INSN_CLASS_STR = [ "BPF_LD", "BPF_LDX", "BPF_ST", "BPF_STX", "BPF_ALU32", "BPF_JMP", "BPF_JMP32", "BPF_ALU64" ]


BPF_X=0x08
BPF_K=0x00

BPF_MEM=0x60



BPF_JA   =0x00 #  /* BPF_JMP only */
BPF_JEQ  =0x10
BPF_JGT  =0x20
BPF_JGE  =0x30
BPF_JSET =0x40
BPF_JNE  =0x50 # /* eBPF only: jump != */
BPF_JSGT =0x60 # /* eBPF only: signed '>' */
BPF_JSGE =0x70 # /* eBPF only: signed '>=' */
BPF_CALL =0x80 # /* eBPF BPF_JMP only: function call */
BPF_EXIT =0x90 # /* eBPF BPF_JMP only: function return */
BPF_JLT  =0xa0 # /* eBPF only: unsigned '<' */
BPF_JLE  =0xb0 # /* eBPF only: unsigned '<=' */
BPF_JSLT =0xc0 # /* eBPF only: signed '<' */
BPF_JSLE =0xd0 # /* eBPF only: signed '<=' */

BPF_JMP_TYPES = [BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET, BPF_JNE, BPF_JSGT, BPF_JSGE, BPF_CALL, BPF_EXIT, BPF_JLT, BPF_JLE, BPF_JSLT, BPF_JSLE ]
BPF_JMP_TYPES_STR = ["BPF_JA", "BPF_JEQ", "BPF_JGT", "BPF_JGE", "BPF_JSET", "BPF_JNE", "BPF_JSGT", "BPF_JSGE", "BPF_CALL", "BPF_EXIT", "BPF_JLT", "BPF_JLE", "BPF_JSLT", "BPF_JSLE" ]


BPF_ADD=0x00
BPF_SUB=0x10
BPF_MUL=0x20
BPF_DIV=0x30
BPF_OR =0x40
BPF_AND=0x50
BPF_LSH=0x60
BPF_RSH=0x70
BPF_NEG=0x80
BPF_MOD=0x90
BPF_XOR=0xa0
BPF_MOV=0xb0


BPF_ALU_OPS  = [ BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND, BPF_LSH, BPF_RSH, BPF_NEG, BPF_MOD, BPF_XOR,BPF_MOV]

BPF_ALU_OPS_STR = ["BPF_ADD", "BPF_SUB", "BPF_MUL", "BPF_DIV", "BPF_OR", "BPF_AND", "BPF_LSH", "BPF_RSH", "BPF_NEG", "BPF_MOD", "BPF_XOR",  "BPF_MOV"] 

BPF_REG_0 = 0
BPF_REG_1 = 1
BPF_REG_2 = 2
BPF_REG_3 = 3
BPF_REG_4 = 4
BPF_REG_5 = 5
BPF_REG_6 = 6
BPF_REG_7 = 7
BPF_REG_8 = 8
BPF_REG_9 = 9
BPF_REG_10 = 10

BPF_REG_TO_STR = ["BPF_REG_0", "BPF_REG_1" , "BPF_REG_2" , "BPF_REG_3", "BPF_REG_4", "BPF_REG_5","BPF_REG_6",  "BPF_REG_7",    "BPF_REG_8", "BPF_REG_9", "BPF_REG_10"]


BPF_REG_LIST = [ BPF_REG_0, BPF_REG_1, BPF_REG_2 , BPF_REG_3 , BPF_REG_4 , BPF_REG_5 , BPF_REG_6 , BPF_REG_7 , BPF_REG_8 , BPF_REG_9 , BPF_REG_10 ]
'''
struct bpf_insn {
        __u8    code;           /* opcode */
        __u8    dst_reg:4;      /* dest register */
        __u8    src_reg:4;      /* source register */
        __s16   off;            /* signed offset */
        __s32   imm;            /* signed immediate constant */
};"		
'''

def BPF_OP(code):
    return ((code) & 0xf0)


def print_insn(insn):
    print("{")
    print("code : " + hex(insn["code"]))
    print("dst_reg : " + hex(insn["dst_reg"]))
    print("src_reg : " + hex(insn["src_reg"]))
    print("off : " + hex(insn["off"]))
    print("imm : " + hex(insn["imm"]))
    print("}")


def get_random_bpf_reg(is_src_reg):
    return random.randint(0,9 + is_src_reg) #  R10 can be a source reg 
   
def check_src_register_intiliazed(src_reg):
#    if src_reg == 0:
#        return
    if reg_init[src_reg]:
        print("Register Initialized")
    else:
        print("Register Not Initialized : REG_"+str(src_reg))

def gen_mov_insn(random_insn_list):

    is_64_bit = random.randint(0,1)
    alu_imm = random.randint(0,1)

    op = BPF_MOV
    bpf_alu_class = BPF_ALU64 if is_64_bit == 1 else BPF_ALU
    bpf_op_src = BPF_K if alu_imm == 1 else BPF_X 

    code =  BPF_OP(op) |  bpf_op_src |  bpf_alu_class ;
    dst_reg = get_random_bpf_reg(0);
    src_reg = 0 if alu_imm == 1 else random.choice(BPF_REG_LIST)
    off = 0
    imm = random.randint(-0xffff,0xffff) if alu_imm == 1 else 0
   
    insn = {}
    insn["code"] = code;
    insn["dst_reg"] = dst_reg;
    insn["src_reg"] = src_reg;
    insn["off"] = off;
    insn["imm"] = imm;
    
    random_insn_list.append(insn)
    return random_insn_list


def gen_exit_insn(random_insn_list):
    insn = {}
    insn["code"] = BPF_JMP | BPF_EXIT ;
    insn["dst_reg"] = 0;
    insn["src_reg"] = 0;
    insn["off"] = 0;
    insn["imm"] = 0;
   
    random_insn_list.append(insn)
    return random_insn_list

def gen_jmp_insn(random_insn_list):

    is_64_bit = random.randint(0,1)
    jmp_imm = random.randint(0,1)

    op = random.choice(BPF_JMP_TYPES);

    # to avoid exit 
    if op == BPF_EXIT:
        op += 0x10
    if is_64_bit == 0 and op == BPF_JA:    # JM_JA is only for JMP 64
        op += 0x10
    if op == BPF_CALL:
        op += 0x10


    bpf_jmp_class = BPF_JMP if is_64_bit == 1 else BPF_JMP32
    bpf_op_src = BPF_K if jmp_imm == 1 else BPF_X 

    code =  BPF_OP(op) |  bpf_op_src |  bpf_jmp_class ;
    dst_reg = get_random_bpf_reg(0);
    src_reg = 0 if jmp_imm == 1 else random.choice(BPF_REG_LIST)
    off = random.randint(0,1); # TODO 
    imm = random.randint(0,1) if jmp_imm == 1 else 0

    insn = {}
    insn["code"] = code;
    #print("JMP code " + hex(code) ) 
    insn["dst_reg"] = dst_reg;
    insn["src_reg"] = src_reg;
    insn["off"] = off;
    insn["imm"] = imm;
    
    random_insn_list.append(insn)
    return random_insn_list


def gen_alu_insn(random_insn_list):

    is_64_bit = random.randint(0,1)
    alu_imm = random.randint(0,1)

    op = random.choice(BPF_ALU_OPS);
    bpf_alu_class = BPF_ALU64 if is_64_bit == 1 else BPF_ALU
    bpf_op_src = BPF_K if alu_imm == 1 else BPF_X 

    code =  BPF_OP(op) |  bpf_op_src |  bpf_alu_class ;
    dst_reg = get_random_bpf_reg(0);
    src_reg = 0 if alu_imm == 1 else random.choice(BPF_REG_LIST)
    off = 0
    imm = random.randint(-0xffff,0xffff) if alu_imm == 1 else 0
  
    # limit shift values for LEFT and RIGHT shift OP
    insn_opcode = code & 0xf0
    if insn_opcode == BPF_LSH or insn_opcode == BPF_RSH:
        if imm:
            max_shift =  63 if(is_64_bit) else 31;
            imm = random.randint(0,32)
        
    if insn_opcode == BPF_NEG:
        src_reg = 0 
        imm = 0 
        code = code & 0xf7 # clear the register/imm bit
    insn = {}
    insn["code"] = code;
    insn["dst_reg"] = dst_reg;
    insn["src_reg"] = src_reg;
    insn["off"] = off;
    insn["imm"] = imm;

    random_insn_list.append(insn)
    return random_insn_list



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

ST_TYPE_IMM = 0
ST_TYPE_REG = 1

def gen_st_insn(random_insn_list):

    st_type = random.randint(0,1)

    st_ins_type =  BPF_STX if st_type == ST_TYPE_REG else  BPF_ST
    code = st_ins_type | BPF_DW | BPF_MEM
    insn = {}
    insn["code"] = code;
    dst_reg = get_random_bpf_reg(0);
    insn["dst_reg"] = dst_reg 
    insn["src_reg"] = random.choice(BPF_REG_LIST) if st_type == ST_TYPE_REG else  0
    insn["off"] = random.randint(1,16);
    insn["imm"] = 0  if st_type == ST_TYPE_REG else random.randint(-0xffffffff,0xffffffff); 
   
    #print(hex(code))
    random_insn_list.append(insn)
    return random_insn_list

def gen_ld_insn(random_insn_list):

    insn_list = []

    #ld_type = random.randint(0,2)
    ld_type = 0

    if ld_type == 0:
        code = BPF_LD | BPF_DW | BPF_IMM

    dst_reg = get_random_bpf_reg(0);
    src_reg = 0
    off = 0
    imm = random.randint(-0xffffffff,0xffffffff) 
    
    insn = {}
    insn["code"] = code;
    insn["dst_reg"] = dst_reg;
    insn["src_reg"] = src_reg;
    insn["off"] = off;
    insn["imm"] = imm & 0xffffffff  
    
    random_insn_list.append(insn)

    insn = {}
    insn["code"] = 0;
    insn["dst_reg"] = 0;
    insn["src_reg"] = 0;
    insn["off"] = 0;
    insn["imm"] = (imm >> 32) & 0xffffffff  

    random_insn_list.append(insn)
    
    return random_insn_list


'''
Code Field for 8-bit ALU and MOV

  +----------------+--------+--------------------+
  |   4 bits       |  1 bit |   3 bits           |
  | operation code | source | instruction class  |
  +----------------+--------+--------------------+
  (MSB)                                      (LSB)

For load and store instructions the 8-bit 'code' field is divided as:

  +--------+--------+-------------------+
  | 3 bits | 2 bits |   3 bits          |
  |  mode  |  size  | instruction class |
  +--------+--------+-------------------+
  (MSB)                             (LSB)


'''

def print_mov_insn(insn):
    insn_str = "BPF_MOV64" if (insn["code"] & 0x07 == BPF_ALU64 ) else  "BPF_MOV32"
    insn_str +=  "_REG" if insn["code"] & 0x8 else "_IMM"
    insn_str += "("
    insn_str += BPF_REG_TO_STR[insn["dst_reg"]]
    insn_str += ", "
    insn_str += BPF_REG_TO_STR[insn["src_reg"]] if (insn["code"] & 0x8) else hex(insn["imm"])
    insn_str += "), "
    
    return insn_str


'''
BPF_JMP_REG(OP, DST, SRC, OFF)  
BPF_JMP32_REG(OP, DST, SRC, OFF)  
BPF_JMP_IMM(OP, DST, SRC, OFF)  
BPF_JMP32_IMM(OP, DST, SRC, OFF)  
'''
def print_jmp_insn(insn):

    insn_str =  BPF_INSN_CLASS_STR[ insn["code"] & 0x07 ]
    insn_str +=  "_REG" if insn["code"] & 0x8 else "_IMM"
    insn_str += "("
    insn_str += BPF_JMP_TYPES_STR[ (insn["code"] & 0xf0) >> 4] 
    insn_str += ", "
    insn_str += BPF_REG_TO_STR[insn["dst_reg"]]
    insn_str += ", "
    insn_str += BPF_REG_TO_STR[insn["src_reg"]] if (insn["code"] & 0x8) else hex(insn["imm"])
    insn_str += ", "
    insn_str +=  hex(insn["imm"])
    insn_str += "), "
    return insn_str




def print_alu_insn(insn):
    insn_str =  BPF_INSN_CLASS_STR[ insn["code"] & 0x07 ]
    insn_str +=  "_REG" if insn["code"] & 0x8 else "_IMM"
    insn_str += "("
    insn_str += BPF_ALU_OPS_STR[ (insn["code"] & 0xf0) >> 4] 
    insn_str += ", "
    insn_str += BPF_REG_TO_STR[insn["dst_reg"]]
    insn_str += ", "
    insn_str += BPF_REG_TO_STR[insn["src_reg"]] if (insn["code"] & 0x8) else hex(insn["imm"])
    insn_str += "), "
    return insn_str


def print_ld_64_insn(insn_0,insn_1):
    
    insn_str = "BPF_LD_IMM64"
    insn_str += "("
    insn_str += BPF_REG_TO_STR[insn_0["dst_reg"]]
    insn_str += ", "
    insn_str += hex( insn_1["imm"] <<32 |   insn_0["imm"])  
    insn_str += "), "



    return insn_str 

def print_exit_insn(insn):
    return "BPF_EXIT_INSN(),\n"
    
def _print_bpf_insn_to_str(insn):
   
    insn_str = ""
    insn_class = insn["code"] & 0x07
    if insn_class == BPF_ALU or insn_class == BPF_ALU64:
        insn_opcode = insn["code"] & 0xf0
        if insn_opcode == BPF_MOV:
            return print_mov_insn(insn)
        else:
            return print_alu_insn(insn)

    if insn_class == BPF_JMP or insn_class == BPF_JMP32:
        return print_jmp_insn(insn)

    print("WARNING: no matching opcode : " + hex(insn["code"]) + " " + hex(insn_class))
   
def print_st_insn(insn):

    insn_str = ""
    insn_str +=  "BPF_STX_MEM" if insn["code"] & 0x7 == BPF_STX else "BPF_ST_MEM"
    insn_str += "("
    insn_str += "BPF_DW"
    insn_str += ", "
    insn_str += BPF_REG_TO_STR[insn["dst_reg"]]
    insn_str += ", "
    insn_str += BPF_REG_TO_STR[insn["src_reg"]]  if insn["code"] & 0x7 == BPF_STX  else hex(insn["off"]) 
    insn_str += ", "
    insn_str += "0"  if insn["code"] & 0x7 == BPF_STX  else hex(insn["imm"])
    insn_str += "), "

    return insn_str

def check_dst_reg_needs_initialized(insn):

    if reg_init[insn["dst_reg"]]:
        return True
    insn_class = insn["code"] & 0x07
    if insn_class == BPF_ALU or insn_class == BPF_ALU64:
        insn_opcode = insn["code"] & 0xf0
        if insn_opcode != BPF_MOV:
            return True

    return False


def fix_unintialized(insn_list):
    skip_count = 0
    for index, insn in enumerate(insn_list):
        if skip_count > 0:
            skip_count -= 1
            continue;
        if reg_init[insn["src_reg"]] == False and insn["src_reg"] != BPF_REG_10:

            #print("WARNING REG_" +str(insn["src_reg"]))
            new_insn = {}
            new_insn["code"] = BPF_OP(BPF_MOV) | BPF_K | BPF_ALU
            new_insn["dst_reg"] = insn["src_reg"]
            new_insn["src_reg"] = 0
            new_insn["off"] = 0
            new_insn["imm"] = random.randint(0,0xffffff);
            insn_list.insert(index,new_insn)
            skip_count += 1
            reg_init[ insn["src_reg"]] = True

        if check_dst_reg_needs_initialized(insn) == True:
            new_insn = {}
            new_insn["code"] = BPF_OP(BPF_MOV) | BPF_K | BPF_ALU64
            new_insn["dst_reg"] = insn["dst_reg"]
            new_insn["src_reg"] = 0
            new_insn["off"] = 0
            new_insn["imm"] = random.randint(0,0xffffff);
            insn_list.insert(index,new_insn)
            reg_init[ insn["dst_reg"]] = True
            skip_count += 1

        insn_class =  (insn["code"] & 0x07) 
        if ((insn_class == BPF_ST) or (insn_class == BPF_STX)) and reg_init[insn["dst_reg"]] == False:
            new_insn = {}
            new_insn["code"] = BPF_OP(BPF_MOV) | BPF_X | BPF_ALU64
            new_insn["dst_reg"] = insn["dst_reg"]
            new_insn["src_reg"] = BPF_REG_10 # Stack Pointer
            new_insn["off"] = -1 * random.randint(0,16)
            new_insn["imm"] = 0 
            insn_list.insert(index,new_insn)
            reg_init[ insn["dst_reg"]] = True
            skip_count += 1
 
         
        reg_init[insn["dst_reg"]] == True

    return insn_list
def print_bpf_insn_to_str(insn_list):    

    insn_str = ""
    for index, insn in enumerate(insn_list):
        if insn["code"] == (BPF_LD | BPF_DW | BPF_IMM ) or insn["code"] == 0:
            if  insn["code"] == 0: 
                continue
            insn_str += print_ld_64_insn(insn,insn_list[index+1]) # Next instruction
            insn_str += "\n"
            continue

        if (insn["code"] & 0x7 == BPF_ST) or  (insn["code"] & 0x7  == BPF_STX):
            insn_str += print_st_insn(insn) # Next instruction
            insn_str += "\n"
            continue

        if insn["code"] ==  (BPF_JMP | BPF_EXIT):
            insn_str += print_exit_insn(insn)
            continue


#        print_insn(insn)
        insn_str += _print_bpf_insn_to_str(insn)    
        insn_str += "\n"

    return insn_str



INSN_TYPE_ALU =0
INSN_TYPE_MOV =1
INSN_TYPE_LD  =2
INSN_TYPE_ST  =3
INSN_TYPE_JMP =4
INSN_TYPE_MAX =5

def random_bpf_insn_var_len(target_insn_len):

    insn_len=0;
    random_insn_list = []
    
    while len(random_insn_list) < target_insn_len:
        insn_type = random.randint(0,INSN_TYPE_MAX-1)
    
        if(insn_type == INSN_TYPE_ALU):
            random_insn_list = gen_alu_insn(random_insn_list)
        elif(insn_type == INSN_TYPE_MOV):
            random_insn_list = gen_mov_insn(random_insn_list)
        elif(insn_type == INSN_TYPE_LD):
            random_insn_list = gen_ld_insn(random_insn_list) 
        elif(insn_type == INSN_TYPE_ST):
            random_insn_list = gen_st_insn(random_insn_list)
        elif(insn_type == INSN_TYPE_JMP):
            random_insn_list = gen_jmp_insn(random_insn_list)
    
    # Finish with Exit Instruction
    random_insn_list = gen_exit_insn(random_insn_list)
            
    random_insn_list = fix_unintialized(random_insn_list) 

    return print_bpf_insn_to_str(random_insn_list)
    

 
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

for i  in range(0,11):
    reg_init[i] = False;

if not use_last_code:    
    #random_str = random_bpf_insn_all_class() 
    random_str = random_bpf_insn_var_len(random.randint(2,200) )#to do max_size 
    c_contents  = STR_HEAD + random_str + STR_TAIL

    f = open("bytecode/out.c","w")
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
