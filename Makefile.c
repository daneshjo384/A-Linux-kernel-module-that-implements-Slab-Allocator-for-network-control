obj-m += network_slab_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	sudo insmod network_slab_module.ko

remove:
	sudo rmmod network_slab_module

dmesg:
	dmesg | tail -20