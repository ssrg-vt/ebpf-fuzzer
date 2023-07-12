# eBPF-fuzzer

## Build and Test LKL
0) Install prerequisites
```
sudo apt install -y flex bison libelf-dev clang-15

# install Clang-15
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 15
```

1) Build LKL Kernel

```
git clone --single-branch -b dev https://github.com/ssrg-vt/ebpf-fuzzer.git
cd ebpf-fuzzer
cp lkl_ebpf_config arch/lkl/configs/defconfig
make ARCH=lkl defconfig CC=clang-15
make -C tools/lkl ARCH=lkl CC=clang-15 -j8
```

2) Build the lkl tools

```
cd tools/lkl
make -j8
```

3) Build the sample program


[tools/lkl/bytecode/hello.c](tools/lkl/bytecode/hello.c)

```
./build.sh hello
```


#### Run Random EBPF Generator

```
cd tools/lkl/bytecode/
python3  ebpf_gen.py
```
