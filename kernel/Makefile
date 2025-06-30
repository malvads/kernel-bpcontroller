obj-m += rb_bpwatcher.o

KBUILD_EXTRA_SYMBOLS := $(PWD)/Module.symvers

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(KBUILD_EXTRA_SYMBOLS) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

dkms-rpm:
	sudo $(MAKE) PACKAGE_NAME=$(PACKAGE_NAME) VERSION=$(VERSION) RELEASE=$(RELEASE) -f Makefile.dkms rpm