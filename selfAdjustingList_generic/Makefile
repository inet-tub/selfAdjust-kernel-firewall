obj-m += sal_kern_mod_storage.o
obj-m += sal_kern_mod_memless.o
kern_module = sal_kern_mod_storage.ko

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	insmod $(kern_module)
	dmesg | tail -n 50
	rmmod $(kern_module)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
