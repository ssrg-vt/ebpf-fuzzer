'''
eBPFGenerator Class: Random instruction generator based on eBPF Syntax
'''

import random
import pprint
import subprocess
import sys

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

BPF_LD  = 0x00
BPF_LDX = 0x01
BPF_ST  = 0x02
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


INSN_TYPE_ALU =0
INSN_TYPE_MOV =1
INSN_TYPE_LD  =2
INSN_TYPE_ST  =3
INSN_TYPE_JMP =4
INSN_TYPE_MAX =5

ST_TYPE_IMM = 0
ST_TYPE_REG = 1

class eBPFGenerator:

    reg_init = [None] * 11

    def __init__(self):
        self.random_insn_list = []
        for i  in range(0,11):
            self.reg_init[i] = False;

    # Returns STR
    def generate_instructions(self, target_insn_len):
        while len(self.random_insn_list) < target_insn_len:
            insn_type = random.randint(0,INSN_TYPE_MAX-1)
        
            if(insn_type == INSN_TYPE_ALU):
                self.gen_alu_insn()
            elif(insn_type == INSN_TYPE_MOV):
                self.gen_mov_insn()
            elif(insn_type == INSN_TYPE_LD):
                self.gen_ld_insn() 
            elif(insn_type == INSN_TYPE_JMP):
                self.gen_jmp_insn()
        
        # Finish with Exit Instruction
        self.gen_exit_insn()
        self.fix_unintialized() 

        return self.print_bpf_insn_to_str()

    def gen_mov_insn(self):

        is_64_bit = random.randint(0,1)
        alu_imm = random.randint(0,1)

        op = BPF_MOV
        bpf_alu_class = BPF_ALU64 if is_64_bit == 1 else BPF_ALU
        bpf_op_src = BPF_K if alu_imm == 1 else BPF_X 

        code =  self.BPF_OP(op) |  bpf_op_src |  bpf_alu_class ;
        dst_reg = self.get_random_bpf_reg(0);
        src_reg = 0 if alu_imm == 1 else random.choice(BPF_REG_LIST)
        off = 0
        imm = random.randint(-0xffff,0xffff) if alu_imm == 1 else 0
       
        insn = {}
        insn["code"] = code;
        insn["dst_reg"] = dst_reg;
        insn["src_reg"] = src_reg;
        insn["off"] = off;
        insn["imm"] = imm;
        
        self.random_insn_list.append(insn)


    def gen_exit_insn(self ):
        insn = {}
        insn["code"] = BPF_JMP | BPF_EXIT ;
        insn["dst_reg"] = 0;
        insn["src_reg"] = 0;
        insn["off"] = 0;
        insn["imm"] = 0;
       
        self.random_insn_list.append(insn)

    def gen_jmp_insn(self):

        is_64_bit = random.randint(0,1)
        jmp_imm = random.randint(0,1)

        op = random.choice(BPF_JMP_TYPES);

        # to avoid exit 
        if op == BPF_EXIT:
            op += 0x10
        if is_64_bit == 0 and op == BPF_JA:    # JM_JA is only for JMP 64
            op += 0x10
        if op == BPF_CALL:
            op += 0x20


        bpf_jmp_class = BPF_JMP if is_64_bit == 1 else BPF_JMP32
        bpf_op_src = BPF_K if jmp_imm == 1 else BPF_X 

        code =  self.BPF_OP(op) |  bpf_op_src |  bpf_jmp_class ;
        dst_reg = self.get_random_bpf_reg(0);
        src_reg = 0 if jmp_imm == 1 else random.choice(BPF_REG_LIST)
        off = random.randint(0,1); # TODO 
        imm = random.randint(0,1) if jmp_imm == 1 else 0

        if op==BPF_JA:
            dst_reg = 0
            code = code & (0xf7)  # JA requires only off, clear reg/imm bit
        insn = {}
        insn["code"] = code;
        #print("JMP code " + hex(code) ) 
        insn["dst_reg"] = dst_reg;
        insn["src_reg"] = src_reg;
        insn["off"] = off;
        insn["imm"] = imm;
        
        self.random_insn_list.append(insn)

    def gen_alu_insn(self):

        is_64_bit = random.randint(0,1)
        alu_imm = random.randint(0,1)

        op = random.choice(BPF_ALU_OPS);
        bpf_alu_class = BPF_ALU64 if is_64_bit == 1 else BPF_ALU
        bpf_op_src = BPF_K if alu_imm == 1 else BPF_X 

        code =  self.BPF_OP(op) |  bpf_op_src |  bpf_alu_class ;
        dst_reg = self.get_random_bpf_reg(0);
        src_reg = 0 if alu_imm == 1 else random.choice(BPF_REG_LIST)
        off = 0
        imm = random.randint(-0xffff,0xffff) if alu_imm == 1 else 0
      
        # limit shift values for LEFT and RIGHT shift OP
        insn_opcode = code & 0xf0
        if insn_opcode == BPF_LSH or insn_opcode == BPF_RSH:
            if imm:
                max_shift =  63 if(is_64_bit) else 31;
                imm = random.randint(0,max_shift)
            
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

        self.random_insn_list.append(insn)


    def print_bpf_insn_to_str(self):    

        insn_str = ""
        for index, insn in enumerate(self.random_insn_list):
            if insn["code"] == (BPF_LD | BPF_DW | BPF_IMM ) or insn["code"] == 0:
                if  insn["code"] == 0: 
                    continue
                insn_str += self.print_ld_64_insn(insn,self.random_insn_list[index+1]) # Next instruction
                insn_str += "\n"
                continue

            if (insn["code"] & 0x7 == BPF_ST) or  (insn["code"] & 0x7  == BPF_STX):
                insn_str += self.print_st_insn(insn) # Next instruction
                insn_str += "\n"
                continue

            if insn["code"] ==  (BPF_JMP | BPF_EXIT):
                insn_str += self.print_exit_insn(insn)
                continue


    #        print_insn(insn)
            insn_str += self._print_bpf_insn_to_str(insn)    
            insn_str += "\n"

        return insn_str

    def fix_unintialized(self):
        skip_count = 0
        for index, insn in enumerate(self.random_insn_list):
            if skip_count > 0:
                skip_count -= 1
                continue;
            if self.reg_init[insn["src_reg"]] == False and insn["src_reg"] != BPF_REG_10:

                #print("WARNING REG_" +str(insn["src_reg"]))
                new_insn = {}
                new_insn["code"] = self.BPF_OP(BPF_MOV) | BPF_K | BPF_ALU
                new_insn["dst_reg"] = insn["src_reg"]
                new_insn["src_reg"] = 0
                new_insn["off"] = 0
                new_insn["imm"] = random.randint(0,0xffffff);
                self.random_insn_list.insert(index,new_insn)
                skip_count += 1
            self.reg_init[ insn["src_reg"]] = True

            if self.check_dst_reg_needs_initialized(insn) == True:
                new_insn = {}
                new_insn["code"] = self.BPF_OP(BPF_MOV) | BPF_K | BPF_ALU64
                new_insn["dst_reg"] = insn["dst_reg"]
                new_insn["src_reg"] = 0
                new_insn["off"] = 0
                new_insn["imm"] = random.randint(0,0xffffff);
                self.random_insn_list.insert(index,new_insn)
                self.reg_init[ insn["dst_reg"]] = True
                skip_count += 1

            insn_class =  (insn["code"] & 0x07) 
            if ((insn_class == BPF_ST) or (insn_class == BPF_STX)) and self.reg_init[insn["dst_reg"]] == False:
                new_insn = {}
                new_insn["code"] = self.BPF_OP(BPF_MOV) | BPF_X | BPF_ALU64
                new_insn["dst_reg"] = insn["dst_reg"]
                new_insn["src_reg"] = BPF_REG_10 # Stack Pointer
                new_insn["off"] = -1 * random.randint(0,16)
                new_insn["imm"] = 0 
                self.random_insn_list.insert(index,new_insn)
                self.reg_init[ insn["dst_reg"]] = True
                skip_count += 1
     
             
        self.reg_init[insn["dst_reg"]] == True

    def gen_st_insn(self):

        st_type = random.randint(0,1)

        st_ins_type =  BPF_STX if st_type == ST_TYPE_REG else  BPF_ST
        code = st_ins_type | BPF_DW | BPF_MEM
        insn = {}
        insn["code"] = code;
        dst_reg = self.get_random_bpf_reg(0);
        insn["dst_reg"] = dst_reg 
        insn["src_reg"] = random.choice(BPF_REG_LIST) if st_type == ST_TYPE_REG else  0
        insn["off"] = random.randint(1,16);
        insn["imm"] = 0  if st_type == ST_TYPE_REG else random.randint(-0xffffffff,0xffffffff); 
       
        self.random_insn_list.append(insn)

    def gen_ld_insn(self):

        insn_list = []

        #ld_type = random.randint(0,2)
        ld_type = 0

        if ld_type == 0:
            code = BPF_LD | BPF_DW | BPF_IMM

        dst_reg = self.get_random_bpf_reg(0);
        src_reg = 0
        off = 0
        imm = random.randint(-0xffffffff,0xffffffff) 
        
        insn = {}
        insn["code"] = code;
        insn["dst_reg"] = dst_reg;
        insn["src_reg"] = src_reg;
        insn["off"] = off;
        insn["imm"] = imm & 0xffffffff  
        
        self.random_insn_list.append(insn)

        insn = {}
        insn["code"] = 0;
        insn["dst_reg"] = 0;
        insn["src_reg"] = 0;
        insn["off"] = 0;
        insn["imm"] = (imm >> 32) & 0xffffffff  

        self.random_insn_list.append(insn)
        


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

    def print_mov_insn(self,insn):
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
    def print_jmp_insn(self,insn):

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

    def print_alu_insn(self,insn):
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

    def print_ld_64_insn(self,insn_0,insn_1):
        
        insn_str = "BPF_LD_IMM64"
        insn_str += "("
        insn_str += BPF_REG_TO_STR[insn_0["dst_reg"]]
        insn_str += ", "
        insn_str += hex( insn_1["imm"] <<32 |   insn_0["imm"])  
        insn_str += "), "

        return insn_str 

    def print_exit_insn(self,insn):
        return "BPF_EXIT_INSN(),\n"
        
    def _print_bpf_insn_to_str(self,insn):
       
        insn_str = ""
        insn_class = insn["code"] & 0x07
        if insn_class == BPF_ALU or insn_class == BPF_ALU64:
            insn_opcode = insn["code"] & 0xf0
            if insn_opcode == BPF_MOV:
                return self.print_mov_insn(insn)
            else:
                return self.print_alu_insn(insn)

        if insn_class == BPF_JMP or insn_class == BPF_JMP32:
            return self.print_jmp_insn(insn)

        print("WARNING: no matching opcode : " + hex(insn["code"]) + " " + hex(insn_class))
       
    def print_st_insn(self,insn):

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

    def BPF_OP(self,code):
        return ((code) & 0xf0)

    def print_insn(self,insn):
        print("{")
        print("code : " + hex(insn["code"]))
        print("dst_reg : " + hex(insn["dst_reg"]))
        print("src_reg : " + hex(insn["src_reg"]))
        print("off : " + hex(insn["off"]))
        print("imm : " + hex(insn["imm"]))
        print("}")

    def get_random_bpf_reg(self,is_src_reg):
        return random.randint(0,9 + is_src_reg) #  R10 can be a source reg 

    def check_dst_reg_needs_initialized(self,insn):

        if self.reg_init[insn["dst_reg"]]:
            return True
        insn_class = insn["code"] & 0x07
        if insn_class == BPF_ALU or insn_class == BPF_ALU64:
            insn_opcode = insn["code"] & 0xf0
            if insn_opcode != BPF_MOV:
                return True
        if insn_class == BPF_JMP or BPF_JMP32:
            return True

        return False
