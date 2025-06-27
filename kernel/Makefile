obj-m += rb_bpwatcher.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

dkms-rpm:
	sudo $(MAKE) PACKAGE_NAME=$(PACKAGE_NAME) VERSION=$(VERSION) RELEASE=$(RELEASE) -f Makefile.dkms rpm