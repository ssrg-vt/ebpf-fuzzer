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

```
./build.sh hello
```
