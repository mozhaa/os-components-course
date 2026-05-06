#include "bpf_fw.skel.h"
#include <bpf/libbpf.h>
#include <net/if.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <interface> [ports...]\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    struct rlimit rlim = {.rlim_cur = 128 * 1024 * 1024, .rlim_max = 128 * 1024 * 1024};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit");
        return 1;
    }

    struct bpf_fw_bpf *skel = bpf_fw_bpf__open_and_load();
    if (!skel)
        return 1;

    struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, "xdp_drop_ssh");
    if (!prog) {
        fprintf(stderr, "program not found\n");
        return 1;
    }

    __u8 one = 1;

    for (int i = 2; i < argc; ++i) {
        int port = strtol(argv[i], 0, 10);
        if (bpf_map__update_elem(skel->maps.blocked_ports, &port, sizeof(port), &one, sizeof(one), BPF_ANY)) {
            fprintf(stderr, "failed to add port %d to map\n", port);
            return 1;
        } else {
            fprintf(stderr, "added port %d to map\n", port);
        }
    }
    
    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        fprintf(stderr, "failed to attach xdp\n");
        return 1;
    }
    
    fprintf(stderr, "attached\n");
    pause();

    bpf_link__destroy(link);
    bpf_fw_bpf__destroy(skel);
    return 0;
}