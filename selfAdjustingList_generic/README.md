# Prerequisites
- kernel headers need to be installed
# Run
1. execute `make`
2. this creates a sal_kernel_module.ko
3. execute `sudo insmod sal_kernel_module.ko`
4. this inserts the module into kernel space
5. output can be reviewed with `dmesg`
6. to remove module again `sudo rmmod sal_kernel_module.ko`
7. `make install` runs all the commands (1-6)

## Why a kernel test module

- User space has its limitations to use certain kernel header `list.h` for example can not be easily included
- It's closer to the final environment, since the data structure will live in Kernel space
- The tests will be executed when the module is inserted
- Be aware of this code may crash your system 