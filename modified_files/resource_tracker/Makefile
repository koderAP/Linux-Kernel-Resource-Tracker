obj-m := tracker_module.o 
obj-m += resource_tracker_cleaner.o
obj-y := resource_tracker.o 
obj-y += resource_tracker_hooks.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules


clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

modules:
	@if lsmod | grep -q tracker_module; then \
		echo "Unloading tracker_module..."; \
		sudo rmmod tracker_module; \
	fi
	@if lsmod | grep -q resource_tracker_cleaner; then \
		echo "Unloading resource_tracker_cleaner..."; \
		sudo rmmod resource_tracker_cleaner; \
	fi

	$(MAKE) -C $(KDIR) M=$(PWD) tracker_module.ko
	$(MAKE) -C $(KDIR) M=$(PWD) resource_tracker_cleaner.ko

	sudo insmod tracker_module.ko
	sudo insmod resource_tracker_cleaner.ko
