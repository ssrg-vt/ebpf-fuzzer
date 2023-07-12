if test -f "final.profdata"; then
    llvm-profdata-15 merge -sparse $1.profraw final.profdata  -o  final.profdata
else
    llvm-profdata-15 merge -sparse $1.profraw   -o  final.profdata
fi
