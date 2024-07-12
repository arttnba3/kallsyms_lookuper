LINUX_KERNEL_SRC=/lib/modules/$(shell uname -r)/build
SRC_PATH := $(shell pwd)

all:
	make -C $(LINUX_KERNEL_SRC) M=$(SRC_PATH) modules

clean:
	make -C $(LINUX_KERNEL_SRC) M=$(SRC_PATH) clean
