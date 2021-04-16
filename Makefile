obj-m := pid_page_tables.o

KDIR := /home/miracle/work/linux_kernel/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf .*cmd *.o *.mod.c *.ko .tmp_versions *.order *symvers *Module.markers

