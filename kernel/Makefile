CONFIG_STACK_VALIDATION=

ccflags-y  :=  -I/usr/include -I../ebpf/headers

obj-m += iptables-trace.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
