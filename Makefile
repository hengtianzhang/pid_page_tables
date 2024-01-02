KVERS := $(shell uname -r)

obj-m := pid_page_tables.o

build: kernel_modules

kernel_modules:
	$(MAKE) -C /lib/modules/$(KVERS)/build M=$(CURDIR) modules

clean:
	$(MAKE) -C /lib/modules/$(KVERS)/build M=$(CURDIR) clean
