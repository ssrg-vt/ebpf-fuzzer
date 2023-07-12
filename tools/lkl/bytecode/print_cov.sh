# Sample Output of 'llvm-cov-15 report' :
#
# Name                                            Regions    Miss   Cover     Lines    Miss   Cover  Branches    Miss   Cover
# ---------------------------------------------------------------------------------------------------------------------------

seconds=$1
missing_regions=`llvm-cov-15 report  --show-functions ../../../kernel/bpf/verifier.o   --instr-profile final.profdata  ../../../kernel/bpf  |   grep TOTAL |  awk '{print $3}'`
total_regions=`llvm-cov-15 report  --show-functions ../../../kernel/bpf/verifier.o   --instr-profile final.profdata  ../../../kernel/bpf  |   grep TOTAL |  awk '{print $2}'`

covered_regions=$((total_regions-missing_regions))
echo Time: ${seconds} secs, Basic-Block Coverage: ${covered_regions}/${total_regions} 
echo ${seconds},${covered_regions} >> graph.csv
