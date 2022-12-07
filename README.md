
#### Build and Test LKL
1) Build LKL Kernel

```
cp lkl_ebpf_config arch/lkl/configs/defconfig
make ARCH=lkl defconfig 
make ARCH=lkl -j8
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
