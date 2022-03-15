KERNEL_SRC_PATH = /usr/src/linux-source-5.11.0/linux-source-5.11.0/

copy:
	@echo Copying files to $(KERNEL_SRC_PATH)
	cp -r ./include/ $(KERNEL_SRC_PATH)
	cp -r ./net/ $(KERNEL_SRC_PATH)

compile:
	sudo make -C $(KERNEL_SRC_PATH) -j 4

install_module:
	lsmod | grep nf_tables && (nft flush ruleset; rmmod nf_tables; insmod $(KERNEL_SRC_PATH)net/netfilter/nf_tables.ko)
