// Use the target SDK's kinfo_proc layout, not a hand-coded Rust ABI.
#include <errno.h>
#include <libproc.h>
#include <string.h>
#include <sys/sysctl.h>

int seccy_kernel_process(pid_t pid, struct proc_bsdinfo *out) {
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc k = {0};
    size_t size = sizeof(k);
    if (sysctl(mib, 4, &k, &size, NULL, 0) < 0) return errno;
    if (size != sizeof(k) || k.kp_proc.p_pid != pid) return ESRCH;
    memset(out, 0, sizeof(*out));
    out->pbi_pid = pid;
    out->pbi_ppid = k.kp_eproc.e_ppid;
    out->pbi_pgid = k.kp_eproc.e_pgid;
    out->pbi_uid = k.kp_eproc.e_ucred.cr_uid;
    out->pbi_gid = k.kp_eproc.e_ucred.cr_groups[0];
    out->pbi_ruid = k.kp_eproc.e_pcred.p_ruid;
    out->pbi_rgid = k.kp_eproc.e_pcred.p_rgid;
    out->e_tdev = k.kp_eproc.e_tdev;
    out->e_tpgid = k.kp_eproc.e_tpgid;
    out->pbi_start_tvsec = k.kp_proc.p_starttime.tv_sec;
    out->pbi_start_tvusec = k.kp_proc.p_starttime.tv_usec;
    strlcpy(out->pbi_name, k.kp_proc.p_comm, sizeof(out->pbi_name));
    return 0;
}
