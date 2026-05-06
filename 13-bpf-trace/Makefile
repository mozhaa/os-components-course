bpf_trace_loader: bpf_trace.bpf.o bpf_trace_loader.c bpf_trace.skel.h
	gcc -O2 -Wall -Wextra bpf_trace_loader.c -o bpf_trace_loader -lbpf

bpf_trace.skel.h: bpf_trace.bpf.o
	/usr/local/sbin/bpftool gen skeleton bpf_trace.bpf.o > bpf_trace.skel.h

bpf_trace.bpf.o: bpf_trace.bpf.c vmlinux.h
	clang -O2 -Wall -Wextra -g -target bpf -c bpf_trace.bpf.c -o bpf_trace.bpf.o

vmlinux.h:
	sudo /usr/local/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c >vmlinux.h

clean:
	rm *.o bpf_trace_loader
