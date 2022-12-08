import random
from eBPFGenerator import eBPFGenerator
import cLoaderProg
import os

import subprocess


def triage_failure(verifier_out):
   print("===Triage=====")
   print(verifier_out[len(verifier_out)-5])



def check_verification_status(out):

    st = True
    output_lines = out.split("\n")
    for index,line in enumerate(output_lines) :
#        print(line)
        if "BPF Verification Failed" in line:
            st = False
            triage_failure(output_lines[index:])
        if "ASSERT_ERROR" in  line:
            print("===============ALU_ERROR=============")
#            val = input("")
    return st


def run_single_ebpf_prog():
    
    ebpf_gen = eBPFGenerator()
    random_str = ebpf_gen.generate_instructions(random.randint(2,10) )#to do max_size 
    #c_contents  = cLoaderProg.LOADER_PROG_HEAD + random_str + cLoaderProg.LOADER_PROG_TAIL
    c_contents  = cLoaderProg.LOADER_PROG_HEAD + cLoaderProg.LOADER_PROG_EXPLOIT + random_str +  cLoaderProg.LOADER_PROG_TAIL
    #filename = "out_" + hex(random.randint(0xffffff, 0xfffffffffff))[2:]
    filename = "test"
    f = open(filename+".c","w")
    f.write(c_contents)
    f.close()


    os.sync()
    filename = "map"
    build_cmd = "bash ./build.sh " + filename 
    build_out = subprocess.run(build_cmd.split(' '))

    # Execute 
    exec_cmd = "./" + filename
    ebpf_out = subprocess.run(exec_cmd.split(' '),stdout=subprocess.PIPE)

    ebpf_out = ebpf_out.stdout.decode("utf-8")

    if(check_verification_status(ebpf_out)):
        print("Verification Passed")
    else:
        print("Verification Failed")
    #print(random_str)


run_single_ebpf_prog()

