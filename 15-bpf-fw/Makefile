bpf_fw_loader: bpf_fw.bpf.o bpf_fw_loader.c bpf_fw.skel.h
	gcc -O2 -Wall -Wextra bpf_fw_loader.c -o bpf_fw_loader -lbpf

bpf_fw.skel.h: bpf_fw.bpf.o
	/usr/local/sbin/bpftool gen skeleton bpf_fw.bpf.o > bpf_fw.skel.h

bpf_fw.bpf.o: bpf_fw.bpf.c vmlinux.h
	clang -O2 -Wall -Wextra -g -target bpf -c bpf_fw.bpf.c -o bpf_fw.bpf.o

vmlinux.h:
	sudo /usr/local/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c >vmlinux.h

clean:
	rm *.o bpf_fw_loader
