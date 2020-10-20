obj-m := hook.o
KDIR = /lib/modules/$(shell uname -r)/build
PWD =$(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	rm -rf *.mod *.a *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers *.order