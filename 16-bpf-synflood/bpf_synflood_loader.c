#include "bpf_synflood.skel.h"
#include <bpf/libbpf.h>
#include <net/if.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
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

    struct bpf_synflood_bpf *skel = bpf_synflood_bpf__open_and_load();
    if (!skel)
        return 1;

    struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, "xdp_filter_tcp");
    if (!prog) {
        fprintf(stderr, "program not found\n");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        fprintf(stderr, "failed to attach xdp\n");
        return 1;
    }
    
    fprintf(stderr, "attached\n");
    pause();

    bpf_link__destroy(link);
    bpf_synflood_bpf__destroy(skel);
    return 0;
}