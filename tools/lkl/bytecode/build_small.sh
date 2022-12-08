
if [ -z "$1" ]; then
	echo "No program name provided"
	echo "Usage: "
	echo " $0 <obj> "
	exit
fi 

#echo "Compiling LKL executable:  $1\n"
OBJ=$1

gcc -fPIC -pthread  -I../include  -g  -D"BUILD_STR(s)=#s" -c -o ${OBJ}.o ${OBJ}.c ;
ld -r -o ${OBJ}-in.o ${OBJ}.o ;
gcc -pie  -o  ${OBJ} ${OBJ}-in.o ../liblkl.a -lrt -lpthread -larchive

