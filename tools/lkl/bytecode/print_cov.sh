
#llvm-profdata-15 merge -sparse $1.profraw final.profdata -o  final.profdata

#llvm-cov-15 report ./$1 -instr-profile=final.profdata -show-functions  ../../../kernel/bpf/verifier.c     | grep TOTAL 

#llvm-cov-15 report  --show-functions ../../../kernel/bpf/verifier.o     --instr-profile final.profdata  ../../../kernel/bpf  | grep TOTAL

seconds=$1
regions=`llvm-cov-15 report  --show-functions ../../../kernel/bpf/verifier.o   --instr-profile final.profdata  ../../../kernel/bpf  |   grep TOTAL |  awk '{print $3}'`
echo ${seconds},${regions} 
echo ${seconds},${regions} >> graph.csv
