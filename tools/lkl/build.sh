






#gcc -fPIC -pthread  -Iinclude  -g  -D"BUILD_STR(s)=#s" -c -o my_boot.o my_boot.c ; ld -r -o my_boot-in.o my_boot.o ;gcc -pie  -o  my_boot my_boot-in.o liblkl.a -lrt -lpthread -larchive

if [ -z "$1" ]; then
	echo "No program name provided"
	echo "Usage: "
	echo " $0 <obj> "
	exit
fi 

echo "Compiling LKL executable:  $1\n"
OBJ=$1

gcc -fPIC -pthread  -Iinclude  -g  -D"BUILD_STR(s)=#s" -c -o ${OBJ}.o bytecode/${OBJ}.c ;
ld -r -o ${OBJ}-in.o ${OBJ}.o ;
gcc -pie  -o  ${OBJ} ${OBJ}-in.o liblkl.a -lrt -lpthread -larchive

