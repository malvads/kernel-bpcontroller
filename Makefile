all: rpm

# rpm mock
rpm:
	$(MAKE) -C packaging/rpm

rpmtest:
	$(MAKE) LATEST=`git stash create` -C packaging/rpm

dkms-rpm:
	cd kernel; $(MAKE) dkms-rpm