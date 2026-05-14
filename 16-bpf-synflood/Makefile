bpf_synflood_loader: bpf_synflood.bpf.o bpf_synflood_loader.c bpf_synflood.skel.h
	gcc -O2 -Wall -Wextra bpf_synflood_loader.c -o bpf_synflood_loader -lbpf

bpf_synflood.skel.h: bpf_synflood.bpf.o
	/usr/local/sbin/bpftool gen skeleton bpf_synflood.bpf.o > bpf_synflood.skel.h

bpf_synflood.bpf.o: bpf_synflood.bpf.c vmlinux.h
	clang -O2 -Wall -Wextra -g -target bpf -c bpf_synflood.bpf.c -o bpf_synflood.bpf.o

vmlinux.h:
	sudo /usr/local/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c >vmlinux.h

clean:
	rm *.o bpf_synflood_loader
