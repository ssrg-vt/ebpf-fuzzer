OBJ=$1

if [ -z "$1" ]; then
	echo "No program name provided"
	echo "Usage: "
	echo " $0 <obj> "
	exit
fi 

clang-15 -fprofile-instr-generate -fcoverage-mapping -fPIC -pthread  -I../include  -g  -D"BUILD_STR(s)=#s" -c -o ${OBJ}.o ${OBJ}.c ;
ld -r -o ${OBJ}-in.o ${OBJ}.o ;
clang-15 -fprofile-instr-generate -fcoverage-mapping -pie  -o  ${OBJ} ${OBJ}-in.o ../liblkl.a -lrt -lpthread 
