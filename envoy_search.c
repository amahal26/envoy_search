#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <io.h>
#include <regex.h>

# define setlocale(Category, Locale) //from "nls.h"
# define bindtextdomain(Domain, Directory) //from "nls.h"
# define textdomain(Domain) //from "nls.h"
#define EPIPE 32 //from "errno.h"
#define PROCPATHLEN 64  // must hold /proc/2000222000/task/2000222000/cmdline
#define EXIT_FATAL 3
#define PIDS_VAL( relative_enum, type, stack, info ) \
    stack -> head [ relative_enum ] . result . type
#   define program_invocation_short_name \
		prog_inv_sh_nm_from_file(__FILE__, 1)

static int opt_newest = 0;
static char *opt_pattern = "envoy";
extern int optind; //オプション以外の文字列の先頭へのインデックス
static int opt_threads = 0;
static int opt_negate = 0;
static const char *opt_delim = "\n";

struct el {
    long    num;
    char *    str;
};

void close_stdout(void)
{
	if (close_stream(stdout) != 0 && !(errno == EPIPE)) {
		char const *write_error = _("write error");
		error(0, errno, "%s", write_error);
		_exit(EXIT_FAILURE);
	}

	if (close_stream(stderr) != 0)
		_exit(EXIT_FAILURE);
}

struct option		/* specification for a long form option...	*/
{
  const char *name;		/* option name, without leading hyphens */
  int         has_arg;		/* does it take an argument?		*/
  int        *flag;		/* where to save its status, or NULL	*/
  int         val;		/* its associated status value		*/
};

enum    		/* permitted values for its `has_arg' field...	*/
{
  no_argument = 0,      	/* option never takes an argument	*/
  required_argument,		/* option always requires an argument	*/
  optional_argument		/* option may take an argument		*/
};

static enum {
    PGREP = 0,
    PKILL,
} prog_mode;

enum {
    SIGNAL_OPTION = CHAR_MAX + 1,
    NS_OPTION,
    NSLIST_OPTION,
    CGROUP_OPTION,
};
static const struct option longopts[] = {
    {"newest", no_argument, NULL, 'n'}, //*name="newest", has_arg=0, *flag=NULL, val='n'
    {NULL, 0, NULL, 0}
};

static void parse_opts (int argc, char **argv) //オプションの解析と検索文字列の設定
{
    char opts[64] = "";
    int opt;
    int criteria_count = 0;

    strcat (opts, "lad:vw"); //optsの末尾に"lad:vw"を連結
        prog_mode = PGREP; //prog_mode=0

    strcat (opts,"LF:cfinoxP:O:g:s:u:U:G:t:r:?Vh"); //optsの末尾に"LF:cfinoxP:O:g:s:u:U:G:t:r:?Vh"を連結.よってopts="lad:vwLF:cfinoxP:O:g:s:u:U:G:t:r:?Vh"

    while ((opt = getopt_long (argc, argv, opts, longopts, NULL)) != -1) { //オプションがないか引数リストの最後まで繰り返し
        opt_newest = 1;
        ++criteria_count;
        break;
    }

    if (argc - optind == 1) //opt_patternに引数に与えられた文字列を代入
        opt_pattern = argv[optind];
}

struct pids_counts { //from"pid.h"
    int total;
    int running, sleeping, stopped, zombied, other;
};

struct pids_result {
    enum pids_item item;
    union {
        signed char         s_ch;
        signed int          s_int;
        unsigned int        u_int;
        unsigned long       ul_int;
        unsigned long long  ull_int;
        char               *str;
        char              **strv;
    } result;
};

struct pids_stack {
    struct pids_result *head;
};

struct pids_fetch { //from"pid.h"
    struct pids_counts *counts;
    struct pids_stack **stacks;
};

struct fetch_support { //from"pid.c"
    struct pids_stack **anchor;        // reap/select consolidated extents
    int n_alloc;                       // number of above pointers allocated
    int n_inuse;                       // number of above pointers occupied
    int n_alloc_save;                  // last known results.stacks allocation
    struct pids_fetch results;         // counts + stacks for return to caller
    struct pids_counts counts;         // actual counts pointed to by 'results'
};

enum namespace_type { //from"misc.h"
    PROCPS_NS_IPC,
    PROCPS_NS_MNT,
    PROCPS_NS_NET,
    PROCPS_NS_PID,
    PROCPS_NS_USER,
    PROCPS_NS_UTS,
    PROCPS_NS_COUNT  // total namespaces (fencepost)
};

struct procps_ns { //from"misc.h"
    unsigned long ns[PROCPS_NS_COUNT];
};

typedef struct proc_t { //from "readproc.h"
    int
        tid,            // (special)       task id, the POSIX thread ID (see also: tgid)
        ppid;           // stat,status     pid of parent process
    char
        state,          // stat,status     single-char code for process state (S=sleeping)
        pad_1,          // n/a             padding
        pad_2,          // n/a             padding
        pad_3;          // n/a             padding
    unsigned long long
        utime,          // stat            user-mode CPU time accumulated by process
        stime,          // stat            kernel-mode CPU time accumulated by process
        cutime,         // stat            cumulative utime of process and reaped children
        cstime,         // stat            cumulative stime of process and reaped children
        start_time,     // stat            start time of process -- seconds since system boot
        blkio_tics,     // stat            time spent waiting for block IO
        gtime,          // stat            guest time of the task in jiffies
        cgtime;         // stat            guest time of the task children in jiffies
    int                 // next 3 fields are NOT filled in by readproc
        pcpu,           // stat (special)  elapsed tics for %CPU usage calculation
        maj_delta,      // stat (special)  major page faults since last update
        min_delta;      // stat (special)  minor page faults since last update
    char
        // Linux 2.1.7x and up have 64 signals. Allow 64, plus '\0' and padding.
        signal[18],     // status          mask of pending signals
        blocked[18],    // status          mask of blocked signals
        sigignore[18],  // status          mask of ignored signals
        sigcatch[18],   // status          mask of caught  signals
        _sigpnd[18];    // status          mask of PER TASK pending signals
    unsigned long
        start_code,     // stat            address of beginning of code segment
        end_code,       // stat            address of end of code segment
        start_stack,    // stat            address of the bottom of stack for the process
        kstk_esp,       // stat            kernel stack pointer
        kstk_eip,       // stat            kernel instruction pointer
        wchan,          // stat (special)  address of kernel wait channel proc is sleeping in
        rss,            // stat            identical to 'resident'
        alarm;          // stat            ?
    int
        priority,       // stat            kernel scheduling priority
        nice;           // stat            standard unix nice level of process
    unsigned long
    // the next 7 members come from /proc/#/statm
        size,           // statm           total virtual memory (as # pages)
        resident,       // statm           resident non-swapped memory (as # pages)
        share,          // statm           shared (mmap'd) memory (as # pages)
        trs,            // statm           text (exe) resident set (as # pages)
        lrs,            // statm           library resident set (always 0 w/ 2.6)
        drs,            // statm           data+stack resident set (as # pages)
        dt;             // statm           dirty pages (always 0 w/ 2.6)
    unsigned long
        vm_size,        // status          equals 'size' (as kb)
        vm_lock,        // status          locked pages (as kb)
        vm_rss,         // status          equals 'rss' and/or 'resident' (as kb)
        vm_rss_anon,    // status          the 'anonymous' portion of vm_rss (as kb)
        vm_rss_file,    // status          the 'file-backed' portion of vm_rss (as kb)
        vm_rss_shared,  // status          the 'shared' portion of vm_rss (as kb)
        vm_data,        // status          data only size (as kb)
        vm_stack,       // status          stack only size (as kb)
        vm_swap,        // status          based on linux-2.6.34 "swap ents" (as kb)
        vm_exe,         // status          equals 'trs' (as kb)
        vm_lib,         // status          total, not just used, library pages (as kb)
        vsize,          // stat            number of pages of virtual memory ...
        rss_rlim,       // stat            resident set size limit?
        flags,          // stat            kernel flags for the process
        min_flt,        // stat            number of minor page faults since process start
        maj_flt,        // stat            number of major page faults since process start
        cmin_flt,       // stat            cumulative min_flt of process and child processes
        cmaj_flt,       // stat            cumulative maj_flt of process and child processes
        rchar,          // io              characters read
        wchar,          // io              characters written
        syscr,          // io              number of read I/O operations
        syscw,          // io              number of write I/O operations
        read_bytes,     // io              number of bytes fetched from the storage layer
        write_bytes,    // io              number of bytes sent to the storage layer
        cancelled_write_bytes, // io       number of bytes truncating pagecache
        smap_Rss,              // smaps_rollup  mapping currently resident in RAM
        smap_Pss,              //    "     Rss divided by total processes sharing it
        smap_Pss_Anon,         //    "     proportional share of 'anonymous' memory
        smap_Pss_File,         //    "     proportional share of 'file' memory
        smap_Pss_Shmem,        //    "     proportional share of 'shmem' memory
        smap_Shared_Clean,     //    "     unmodified shared memory
        smap_Shared_Dirty,     //    "     altered shared memory
        smap_Private_Clean,    //    "     unmodified private memory
        smap_Private_Dirty,    //    "     altered private memory
        smap_Referenced,       //    "     memory marked as referenced/accessed
        smap_Anonymous,        //    "     memory not belonging to any file
        smap_LazyFree,         //    "     memory marked by madvise(MADV_FREE)
        smap_AnonHugePages,    //    "     memory backed by transparent huge pages
        smap_ShmemPmdMapped,   //    "     shmem/tmpfs memory backed by huge pages
        smap_FilePmdMapped,    //    "     file memory backed by huge pages
        smap_Shared_Hugetlb,   //    "     hugetlbfs backed memory *not* counted in Rss/Pss
        smap_Private_Hugetlb,  //    "     hugetlbfs backed memory *not* counted in Rss/Pss
        smap_Swap,             //    "     swapped would-be-anonymous memory (includes swapped out shmem)
        smap_SwapPss,          //    "     the proportional share of 'Swap' (excludes swapped out shmem)
        smap_Locked;           //    "     memory amount locked to RAM
    char
        *environ,       // (special)       environment as string (/proc/#/environ)
        *cmdline,       // (special)       command line as string (/proc/#/cmdline)
        *cgroup,        // (special)       cgroup as string (/proc/#/cgroup)
        *cgname,        // (special)       name portion of above (if possible)
        *supgid,        // status          supplementary gids as comma delimited str
        *supgrp,        // supp grp names as comma delimited str, derived from supgid
       **environ_v,     // (special)       environment string vectors (/proc/#/environ)
       **cmdline_v,     // (special)       command line string vectors (/proc/#/cmdline)
       **cgroup_v;      // (special)       cgroup string vectors (/proc/#/cgroup)
    char
        *euser,         // stat(),status   effective user name
        *ruser,         // status          real user name
        *suser,         // status          saved user name
        *fuser,         // status          filesystem user name
        *rgroup,        // status          real group name
        *egroup,        // status          effective group name
        *sgroup,        // status          saved group name
        *fgroup,        // status          filesystem group name
        *cmd;           // stat,status     basename of executable file in call to exec(2)
    int
        rtprio,         // stat            real-time priority
        sched,          // stat            scheduling class
        pgrp,           // stat            process group id
        session,        // stat            session id
        nlwp,           // stat,status     number of threads, or 0 if no clue
        tgid,           // (special)       thread group ID, the POSIX PID (see also: tid)
        tty;            // stat            full device number of controlling terminal
        /* FIXME: int uids & gids should be uid_t or gid_t from pwd.h */
        uid_t euid; gid_t egid; // stat(),status effective
        uid_t ruid; gid_t rgid; // status        real
        uid_t suid; gid_t sgid; // status        saved
        uid_t fuid; gid_t fgid; // status        fs (used for file access only)
    int
        tpgid,          // stat            terminal process group id
        exit_signal,    // stat            might not be SIGCHLD
        processor;      // stat            current (or most recent?) CPU
    int
        oom_score,      // oom_score       (badness for OOM killer)
        oom_adj;        // oom_adj         (adjustment to OOM score)
    struct procps_ns ns; // (ns subdir)     inode number of namespaces
    char
        *sd_mach,       // n/a             systemd vm/container name
        *sd_ouid,       // n/a             systemd session owner uid
        *sd_seat,       // n/a             systemd login session seat
        *sd_sess,       // n/a             systemd login session id
        *sd_slice,      // n/a             systemd slice unit
        *sd_unit,       // n/a             systemd system unit id
        *sd_uunit;      // n/a             systemd user unit id
    char
        *lxcname,       // n/a             lxc container name
        *exe;           // exe             executable path + name
    int
        luid,           // loginuid        user id at login
        autogrp_id,     // autogroup       autogroup number (id)
        autogrp_nice;   // autogroup       autogroup nice value
} proc_t;

struct dirent //from "dirent.h"
{
	long		d_ino;		/* Always zero. */
	unsigned short	d_reclen;	/* Always zero. */
	unsigned short	d_namlen;	/* Length of name in d_name. */
	char		d_name[260]; /* [FILENAME_MAX] */ /* File name. */
};

typedef struct //from "dirent.h"
{
	/* disk transfer area for this dir */
	struct _finddata_t	dd_dta;

	/* dirent struct to return from dir (NOTE: this makes this thread
	 * safe as long as only one thread uses a particular DIR struct at
	 * a time) */
	struct dirent		dd_dir;

	/* _findnext handle */
	intptr_t		dd_handle;

	/*
	 * Status of search:
	 *   0 = not started yet (next entry to read is first entry)
	 *  -1 = off the end
	 *   positive = 0 based index of next entry
	 */
	int			dd_stat;

	/* given path for dir with search pattern (struct is extended) */
	char			dd_name[1];
} DIR;

typedef struct PROCTAB { //from "readproc.h"
    DIR        *procfs;
//    char deBug0[64];
    DIR        *taskdir;  // for threads
//    char deBug1[64];
    pid_t       taskdir_user;  // for threads
    int(*finder)(struct PROCTAB *__restrict const, proc_t *__restrict const);
    proc_t*(*reader)(struct PROCTAB *__restrict const, proc_t *__restrict const);
    int(*taskfinder)(struct PROCTAB *__restrict const, const proc_t *__restrict const, proc_t *__restrict const, char *__restrict const);
    proc_t*(*taskreader)(struct PROCTAB *__restrict const, proc_t *__restrict const, char *__restrict const);
    pid_t      *pids;   // pids of the procs
    uid_t      *uids;   // uids of procs
    int         nuid;   // cannot really sentinel-terminate unsigned short[]
    int         i;  // generic
    unsigned    flags;
    unsigned    u;  // generic
    void *      vp; // generic
    char        path[PROCPATHLEN];  // must hold /proc/2000222000/task/2000222000/cmdline
    unsigned pathlen;        // length of string in the above (w/o '\0')
} PROCTAB;

enum pids_fetch_type { //from "pids.h"
    PIDS_FETCH_TASKS_ONLY,
    PIDS_FETCH_THREADS_TOO
};

struct pids_info { //from "pids.c"
    int refcount;
    int maxitems;                      // includes 'logical_end' delimiter
    int curitems;                      // includes 'logical_end' delimiter
    enum pids_item *items;             // includes 'logical_end' delimiter
    struct stacks_extent *extents;     // anchor for all resettable extents
    struct stacks_extent *otherexts;   // anchor for single stack invariant extents
    struct fetch_support fetch;        // support for procps_pids_reap & select
    int history_yes;                   // need historical data
    struct history_info *hist;         // pointer to historical support data
    proc_t*(*read_something)(PROCTAB*, proc_t*); // readproc/readeither via which
    unsigned pgs2k_shift;              // to convert some proc vaules
    unsigned oldflags;                 // the old library PROC_FILL flagss
    PROCTAB *fetch_PT;                 // oldlib interface for 'select' & 'reap'
    unsigned long hertz;               // for TIME_ALL & TIME_ELAPSED calculations
    unsigned long long boot_seconds;   // for TIME_ELAPSED calculation
    PROCTAB *get_PT;                   // oldlib interface for active 'get'
    struct stacks_extent *get_ext;     // for active 'get' (also within 'extents')
    enum pids_fetch_type get_type;     // last known type of 'get' request
    int seterr;                        // an ENOMEM encountered during assign
    proc_t get_proc;                   // the proc_t used by procps_pids_get
    proc_t fetch_proc;                 // the proc_t used by pids_stacks_fetch
};

enum pids_item { //pids.h
    PIDS_noop,              //        ( never altered )
    PIDS_extra,             //        ( reset to zero )
                            //  returns        origin, see proc(5)
                            //  -------        -------------------
    PIDS_ADDR_CODE_END,     //   ul_int        stat: end_code
    PIDS_ADDR_CODE_START,   //   ul_int        stat: start_code
    PIDS_ADDR_CURR_EIP,     //   ul_int        stat: eip
    PIDS_ADDR_CURR_ESP,     //   ul_int        stat: esp
    PIDS_ADDR_STACK_START,  //   ul_int        stat: start_stack
    PIDS_AUTOGRP_ID,        //    s_int        autogroup
    PIDS_AUTOGRP_NICE,      //    s_int        autogroup
    PIDS_CGNAME,            //      str        derived from CGROUP ':name='
    PIDS_CGROUP,            //      str        cgroup
    PIDS_CGROUP_V,          //     strv        cgroup, as *str[]
    PIDS_CMD,               //      str        stat: tcomm or status: Name
    PIDS_CMDLINE,           //      str        cmdline
    PIDS_CMDLINE_V,         //     strv        cmdline, as *str[]
    PIDS_ENVIRON,           //      str        environ
    PIDS_ENVIRON_V,         //     strv        environ, as *str[]
    PIDS_EXE,               //      str        exe
    PIDS_EXIT_SIGNAL,       //    s_int        stat: exit_signal
    PIDS_FLAGS,             //   ul_int        stat: flags
    PIDS_FLT_MAJ,           //   ul_int        stat: maj_flt
    PIDS_FLT_MAJ_C,         //   ul_int        stat: maj_flt + cmaj_flt
    PIDS_FLT_MAJ_DELTA,     //    s_int        derived from FLT_MAJ
    PIDS_FLT_MIN,           //   ul_int        stat: min_flt
    PIDS_FLT_MIN_C,         //   ul_int        stat: min_flt + cmin_flt
    PIDS_FLT_MIN_DELTA,     //    s_int        derived from FLT_MIN
    PIDS_ID_EGID,           //    u_int        status: Gid
    PIDS_ID_EGROUP,         //      str        derived from EGID, see getgrgid(3)
    PIDS_ID_EUID,           //    u_int        status: Uid
    PIDS_ID_EUSER,          //      str        derived from EUID, see getpwuid(3)
    PIDS_ID_FGID,           //    u_int        status: Gid
    PIDS_ID_FGROUP,         //      str        derived from FGID, see getgrgid(3)
    PIDS_ID_FUID,           //    u_int        status: Uid
    PIDS_ID_FUSER,          //      str        derived from FUID, see getpwuid(3)
    PIDS_ID_LOGIN,          //    s_int        loginuid
    PIDS_ID_PGRP,           //    s_int        stat: pgrp
    PIDS_ID_PID,            //    s_int        from /proc/<pid>
    PIDS_ID_PPID,           //    s_int        stat: ppid or status: PPid
    PIDS_ID_RGID,           //    u_int        status: Gid
    PIDS_ID_RGROUP,         //      str        derived from RGID, see getgrgid(3)
    PIDS_ID_RUID,           //    u_int        status: Uid
    PIDS_ID_RUSER,          //      str        derived from RUID, see getpwuid(3)
    PIDS_ID_SESSION,        //    s_int        stat: sid
    PIDS_ID_SGID,           //    u_int        status: Gid
    PIDS_ID_SGROUP,         //      str        derived from SGID, see getgrgid(3)
    PIDS_ID_SUID,           //    u_int        status: Uid
    PIDS_ID_SUSER,          //      str        derived from SUID, see getpwuid(3)
    PIDS_ID_TGID,           //    s_int        status: Tgid
    PIDS_ID_TID,            //    s_int        from /proc/<pid>/task/<tid>
    PIDS_ID_TPGID,          //    s_int        stat: tty_pgrp
    PIDS_IO_READ_BYTES,     //   ul_int        io: read_bytes
    PIDS_IO_READ_CHARS,     //   ul_int        io: rchar
    PIDS_IO_READ_OPS,       //   ul_int        io: syscr
    PIDS_IO_WRITE_BYTES,    //   ul_int        io: write_bytes
    PIDS_IO_WRITE_CBYTES,   //   ul_int        io: cancelled_write_bytes
    PIDS_IO_WRITE_CHARS,    //   ul_int        io: wchar
    PIDS_IO_WRITE_OPS,      //   ul_int        io: syscw
    PIDS_LXCNAME,           //      str        derived from CGROUP 'lxc.payload'
    PIDS_MEM_CODE,          //   ul_int        derived from MEM_CODE_PGS, as KiB
    PIDS_MEM_CODE_PGS,      //   ul_int        statm: trs
    PIDS_MEM_DATA,          //   ul_int        derived from MEM_DATA_PGS, as KiB
    PIDS_MEM_DATA_PGS,      //   ul_int        statm: drs
    PIDS_MEM_RES,           //   ul_int        derived from MEM_RES_PGS, as KiB
    PIDS_MEM_RES_PGS,       //   ul_int        statm: resident
    PIDS_MEM_SHR,           //   ul_int        derived from MEM_SHR_PGS, as KiB
    PIDS_MEM_SHR_PGS,       //   ul_int        statm: shared
    PIDS_MEM_VIRT,          //   ul_int        derived from MEM_VIRT_PGS, as KiB
    PIDS_MEM_VIRT_PGS,      //   ul_int        statm: size
    PIDS_NICE,              //    s_int        stat: nice
    PIDS_NLWP,              //    s_int        stat: num_threads or status: Threads
    PIDS_NS_IPC,            //   ul_int        ns/
    PIDS_NS_MNT,            //   ul_int         "
    PIDS_NS_NET,            //   ul_int         "
    PIDS_NS_PID,            //   ul_int         "
    PIDS_NS_USER,           //   ul_int         "
    PIDS_NS_UTS,            //   ul_int         "
    PIDS_OOM_ADJ,           //    s_int        oom_score_adj
    PIDS_OOM_SCORE,         //    s_int        oom_score
    PIDS_PRIORITY,          //    s_int        stat: priority
    PIDS_PRIORITY_RT,       //    s_int        stat: rt_priority
    PIDS_PROCESSOR,         //    u_int        stat: task_cpu
    PIDS_PROCESSOR_NODE,    //    s_int        derived from PROCESSOR, see numa(3)
    PIDS_RSS,               //   ul_int        stat: rss
    PIDS_RSS_RLIM,          //   ul_int        stat: rsslim
    PIDS_SCHED_CLASS,       //    s_int        stat: policy
    PIDS_SD_MACH,           //      str        derived from PID/TID, see sd-login(3)
    PIDS_SD_OUID,           //      str         "
    PIDS_SD_SEAT,           //      str         "
    PIDS_SD_SESS,           //      str         "
    PIDS_SD_SLICE,          //      str         "
    PIDS_SD_UNIT,           //      str         "
    PIDS_SD_UUNIT,          //      str         "
    PIDS_SIGBLOCKED,        //      str        status: SigBlk
    PIDS_SIGCATCH,          //      str        status: SigCgt
    PIDS_SIGIGNORE,         //      str        status: SigIgn
    PIDS_SIGNALS,           //      str        status: ShdPnd
    PIDS_SIGPENDING,        //      str        status: SigPnd
    PIDS_SMAP_ANONYMOUS,    //   ul_int        smaps_rollup: Anonymous
    PIDS_SMAP_HUGE_ANON,    //   ul_int        smaps_rollup: AnonHugePages
    PIDS_SMAP_HUGE_FILE,    //   ul_int        smaps_rollup: FilePmdMapped
    PIDS_SMAP_HUGE_SHMEM,   //   ul_int        smaps_rollup: ShmemPmdMapped
    PIDS_SMAP_HUGE_TLBPRV,  //   ul_int        smaps_rollup: Private_Hugetlb
    PIDS_SMAP_HUGE_TLBSHR,  //   ul_int        smaps_rollup: Shared_Hugetlb
    PIDS_SMAP_LAZY_FREE,    //   ul_int        smaps_rollup: LazyFree
    PIDS_SMAP_LOCKED,       //   ul_int        smaps_rollup: Locked
    PIDS_SMAP_PRV_CLEAN,    //   ul_int        smaps_rollup: Private_Clean
    PIDS_SMAP_PRV_DIRTY,    //   ul_int        smaps_rollup: Private_Dirty
    PIDS_SMAP_PRV_TOTAL,    //   ul_int        derived from SMAP_PRV_CLEAN + SMAP_PRV_DIRTY
    PIDS_SMAP_PSS,          //   ul_int        smaps_rollup: Pss
    PIDS_SMAP_PSS_ANON,     //   ul_int        smaps_rollup: Pss_Anon
    PIDS_SMAP_PSS_FILE,     //   ul_int        smaps_rollup: Pss_File
    PIDS_SMAP_PSS_SHMEM,    //   ul_int        smaps_rollup: Pss_Shmem
    PIDS_SMAP_REFERENCED,   //   ul_int        smaps_rollup: Referenced
    PIDS_SMAP_RSS,          //   ul_int        smaps_rollup: Rss
    PIDS_SMAP_SHR_CLEAN,    //   ul_int        smaps_rollup: Shared_Clean
    PIDS_SMAP_SHR_DIRTY,    //   ul_int        smaps_rollup: Shared_Dirty
    PIDS_SMAP_SWAP,         //   ul_int        smaps_rollup: Swap
    PIDS_SMAP_SWAP_PSS,     //   ul_int        smaps_rollup: SwapPss
    PIDS_STATE,             //     s_ch        stat: state or status: State
    PIDS_SUPGIDS,           //      str        status: Groups
    PIDS_SUPGROUPS,         //      str        derived from SUPGIDS, see getgrgid(3)
    PIDS_TICS_ALL,          //  ull_int        stat: stime + utime
    PIDS_TICS_ALL_C,        //  ull_int        stat: stime + utime + cstime + cutime
    PIDS_TICS_ALL_DELTA,    //    u_int        derived from TICS_ALL
    PIDS_TICS_BLKIO,        //  ull_int        stat: blkio_ticks
    PIDS_TICS_GUEST,        //  ull_int        stat: gtime
    PIDS_TICS_GUEST_C,      //  ull_int        stat: gtime + cgtime
    PIDS_TICS_SYSTEM,       //  ull_int        stat: stime
    PIDS_TICS_SYSTEM_C,     //  ull_int        stat: stime + cstime
    PIDS_TICS_USER,         //  ull_int        stat: utime
    PIDS_TICS_USER_C,       //  ull_int        stat: utime + cutime
    PIDS_TIME_ALL,          //  ull_int        derived from (utime + stime) / hertz
    PIDS_TIME_ELAPSED,      //  ull_int        derived from /proc/uptime - (starttime / hertz)
    PIDS_TIME_START,        //  ull_int        stat: start_time
    PIDS_TTY,               //    s_int        stat: tty_nr
    PIDS_TTY_NAME,          //      str        derived from TTY
    PIDS_TTY_NUMBER,        //      str        derived from TTY as str
    PIDS_VM_DATA,           //   ul_int        status: VmData
    PIDS_VM_EXE,            //   ul_int        status: VmExe
    PIDS_VM_LIB,            //   ul_int        status: VmLib
    PIDS_VM_RSS,            //   ul_int        status: VmRSS
    PIDS_VM_RSS_ANON,       //   ul_int        status: RssAnon
    PIDS_VM_RSS_FILE,       //   ul_int        status: RssFile
    PIDS_VM_RSS_LOCKED,     //   ul_int        status: VmLck
    PIDS_VM_RSS_SHARED,     //   ul_int        status: RssShmem
    PIDS_VM_SIZE,           //   ul_int        status: VmSize
    PIDS_VM_STACK,          //   ul_int        status: VmStk
    PIDS_VM_SWAP,           //   ul_int        status: VmSwap
    PIDS_VM_USED,           //   ul_int        status: VmRSS + VmSwap
    PIDS_VSIZE_PGS,         //   ul_int        stat: vsize
    PIDS_WCHAN_NAME         //      str        wchan
};

enum pids_item Items[] = {
    PIDS_ID_PID,
    PIDS_ID_PPID,
    PIDS_ID_PGRP,
    PIDS_ID_EUID,
    PIDS_ID_RUID,
    PIDS_ID_RGID,
    PIDS_ID_SESSION,
    PIDS_ID_TGID,
    PIDS_TIME_START,
    PIDS_TTY_NAME,
    PIDS_CMD,
    PIDS_CMDLINE,
    PIDS_STATE,
    PIDS_TIME_ELAPSED,
    PIDS_CGROUP_V
};

enum rel_items {
    EU_PID, EU_PPID, EU_PGRP, EU_EUID, EU_RUID, EU_RGID, EU_SESSION,
    EU_TGID, EU_STARTTIME, EU_TTYNAME, EU_CMD, EU_CMDLINE, EU_STA, EU_ELAPSED,
    EU_CGROUP
};

static struct el * select_procs (int *num)
{
#define PIDS_GETINT(e) PIDS_VAL(EU_ ## e, s_int, stack, info)
#define PIDS_GETUNT(e) PIDS_VAL(EU_ ## e, u_int, stack, info)
#define PIDS_GETULL(e) PIDS_VAL(EU_ ## e, ull_int, stack, info)
#define PIDS_GETSTR(e) PIDS_VAL(EU_ ## e, str, stack, info)
#define PIDS_GETSCH(e) PIDS_VAL(EU_ ## e, s_ch, stack, info)
#define PIDS_GETSTV(e) PIDS_VAL(EU_ ## e, strv, stack, info)
    struct pids_info *info=NULL;
    struct procps_ns nsp;
    struct pids_stack *stack;
    unsigned long long saved_start_time;      /* for new/old support */
    int saved_pid = 0;                        /* for new/old support */
    int matches = 0;
    int size = 0;
    regex_t *preg;
    pid_t myself = getpid(); //自身のpid
    struct el *list = NULL;
    long cmdlen = get_arg_max() * sizeof(char);
    char *cmdline = xmalloc(cmdlen);
    char *cmdsearch = xmalloc(cmdlen);
    char *cmdoutput = xmalloc(cmdlen);
    char *task_cmdline;
    enum pids_fetch_type which;
    double uptime_secs;

    preg = do_regcomp();

    if (procps_uptime(&uptime_secs, NULL) < 0)
        xerrx(EXIT_FAILURE, "uptime");

    if (opt_newest) saved_start_time =  0ULL; //newestオプションの時にsaved_start_timeにunsigned long longの0を代入する
    else saved_start_time = ~0ULL;  //それ以外はunsigned long longの最大値を代入する

    if (opt_newest) saved_pid = 0; //newestオプションの時にsaved_pidに0を代入する

    if (procps_pids_new(&info, Items, 15) < 0) //新しいpid info構造体の作成に失敗した場合にエラーを返す
        xerrx(EXIT_FATAL,
              _("Unable to create pid info structure"));
    which = PIDS_FETCH_TASKS_ONLY; //whichに列挙型のpids_fetch_typeの一つ目(0)を代入する
    // pkill and pidwait don't support -w, but this is checked in getopt
    if (opt_threads) //lightweightオプションの場合にwhichに列挙型のpids_fetch_typeの二つ目(1)を代入する
        which = PIDS_FETCH_THREADS_TOO;

    while ((stack = procps_pids_get(info, which))) { //pids_stack型の構造体のポインタを順番にstackに代入して繰り返し操作をおこなう
        int match = 1;

        if (PIDS_GETINT(PID) == myself) //自身のpid_infoであれば走査を行わず繰り返しの頭に戻る
            continue;
        else if (opt_newest && PIDS_GETULL(STARTTIME) < saved_start_time) //newestオプションかつプロセスの開始時間がsaved_start_timeに保存された値より小さければmatchに0を代入する
            match = 0;

        task_cmdline = PIDS_GETSTR(CMDLINE); //char型のポインタtask_cmdlineにcmdlineを代入する

        if (match && opt_pattern) { //matchが1かつ引数に与えられた文字列と一致するものが存在する場合
            strncpy (cmdsearch, PIDS_GETSTR(CMD), cmdlen -1); //cmdsearchにPIDS_GETSTR(CMD)の先頭からcmdlen-1文字目までをコピーする
            cmdsearch[cmdlen - 1] = '\0'; //cmdoutputの末尾に終端文字を代入する

            if (regexec (preg, cmdsearch, 0, NULL, 0) != 0) //pregとcmdsearchが一致しなかった場合にmatchに0を代入する
                match = 0;
        }

        if (match ^ opt_negate) {    /* Exclusive OR is neat */ //matchとopt_negateの排他論理和が1の場合
            if (opt_newest) { //newestオプションの場合
                if (saved_start_time == PIDS_GETULL(STARTTIME) && //saved_start_timeとPIDS_GETULL(STARTTIME)が一致かつ
                    saved_pid > PIDS_GETINT(PID)) //saved_pidがPIDS_GETINT(PID)より大きい場合に次の繰り返しへ
                    continue;
                saved_start_time = PIDS_GETULL(STARTTIME); //saved_start_timeにPIDS_GETULL(STARTTIME)を代入
                saved_pid = PIDS_GETINT(PID); //saved_pidにPIDS_GETINT(PID)を代入
                matches = 0; //matchesに0を代入する
            }
            if (matches == size) { //matchesとsize(初期値はともに0)が一致した場合
				grow_size(size); //sizeにsize*5/4+4を代入する
                list = xrealloc(list, size * sizeof *list); //listのメモリサイズをsizeにlistの大きさを掛けたものに変更
            }
            else if (list) { //上記オプション以外の時
                list[matches++].num = PIDS_GETINT(PID); //listの要素数matchesの要素のメンバnumにPIDS_GETINT(PID)を代入してmatchesを+1する
            } else { //それ以外はエラーを返す
                xerrx(EXIT_FATAL, _("internal error"));
            }
        }
    }
    procps_pids_unref(&info);
    free(cmdline); //メモリの開放
    free(cmdsearch); //メモリの開放
    free(cmdoutput); //メモリの開放

    if (preg) {
        regfree(preg); //正規表現のメモリの開放
        free(preg); //メモリの開放
    }

    *num = matches; //ポインタnumの指すメモリにmatchesを代入

    if ((!matches) && opt_pattern && (strlen(opt_pattern) > 15)) //matchesが0かつlist-fullオプション以外かつopt_patternが存在しその長さが15より大きい場合エラーを返す
        xwarnx(_("pattern that searches for process name longer than 15 characters will result in zero matches\n"
                 "Try `%s -f' option to match against the complete command line."),
               program_invocation_short_name);
    return list; //el構造体のポインタであるlistを返す
#undef PIDS_GETINT
#undef PIDS_GETUNT
#undef PIDS_GETULL
#undef PIDS_GETSTR
#undef PIDS_GETSTV
}

static void output_numlist (const struct el *list, int num)
{
    int i;
    const char *delim = opt_delim;
    for (i = 0; i < num; i++) {
        if(i+1==num)
            delim = "\n";
        printf ("%ld%s", list[i].num, delim);
    }
}

int main (int argc, char **argv)
{
    struct el *procs; //long型のnumとchar型のポインタのstr
    int num;
    int i;
    int kill_count = 0;
#ifdef ENABLE_PIDWAIT //test用
    int poll_count = 0;
    int wait_count = 0;
    int epollfd = epoll_create(1);
    struct epoll_event ev, events[32];
#endif

#ifdef HAVE_PROGRAM_INVOCATION_NAME //test用
    program_invocation_name = program_invocation_short_name;
#endif
    setlocale (LC_ALL, ""); //ロケール(国や言語に特有の設定)全体に実行環境の標準の設定をおこなう
    bindtextdomain(PACKAGE, LOCALEDIR); //ドメイン名PACKAGEのメッセージカタログディレクトリをLOCALEDIR(/usr/share/locale)に設定
    textdomain(PACKAGE); //ドメイン名をPACKAGEに設定
    atexit(close_stdout); //終了処理。エラーがなければと特に何もしない。

    parse_opts (argc, argv); //引数のオプションの解析

    procs = select_procs (&num);
    output_numlist (procs,num);
    return !num;

    return -1;
}


