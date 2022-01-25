obj-m += sal_kern_mod_storage.o
obj-m += sal_kern_mod_memless.o
kern_module = sal_kern_mod_storage.ko sal_kern_mod_memless.ko

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	insmod sal_kern_mod_storage.ko
	insmod sal_kern_mod_memless.ko
	dmesg | tail -n 100
	rmmod $(kern_module)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
