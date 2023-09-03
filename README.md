# eBPF-fuzzer

## Build and Test LKL
0) Install prerequisites

Use the docker image 

```
docker pull nkhusain/ebpf_fuzzer
docker run -ti nkhusain/ebpf_fuzzer /bin/bash
```

```
sudo apt install -y flex bison libelf-dev

# install Clang-15
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 15
```

1) Build LKL Kernel

if you used docker, run `docker run -ti nkhusain/ebpf_fuzzer /bin/bash`

```
git clone --single-branch -b dev https://github.com/ssrg-vt/ebpf-fuzzer.git
cd ebpf-fuzzer
cp lkl_ebpf_config arch/lkl/configs/defconfig
make ARCH=lkl defconfig CC=clang-15
```

2) Build the lkl tools

```
make -C tools/lkl ARCH=lkl CC=clang-15 -j8
```

3) Build the sample program


[tools/lkl/bytecode/hello.c](tools/lkl/bytecode/hello.c)

```
cd tools/lkl/bytecode/
./build.sh hello
```


#### Run Random EBPF Generator

```
cd tools/lkl/bytecode/
python3  ebpf_gen.py
```
