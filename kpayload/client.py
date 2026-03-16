import socket, struct, os
from hexdump import hexdump

PS5_IP = os.getenv('PS5_IP')

PAGE_SIZE = 0x4000
PAGE_MASK = PAGE_SIZE - 1

def align_down(val, align):
    return val - val % align

def align_up(val, align):
    return align_down(val + align - 1, align)

def xor_buf(a, b): return bytes([x ^ y for x, y in zip(a, b)])

def make_cmd_hdr(cmd, send_len, resp_len, handle):
    return struct.pack('<IHHQQ', cmd, send_len, resp_len, 0, handle)

def make_sys_mail_hdr(send_len, resp_len, handle):
    return make_cmd_hdr(5, send_len, resp_len, handle)

def make_svc_mail_hdr(handle):
    return make_cmd_hdr(6, 0x80, 0x80, handle)

def pci_cfg_addr(bus, device, function, offset=0):
    MMCFG_BASE = 0xf0000000
    return MMCFG_BASE | (bus << 20) | (device << 15) | (function << 12) | offset

# NOTE For resource management to be reliable, you must use Client in a 'with' statement.
class Client:
    def __init__(self, address=(PS5_IP, 6670)):
        self.c = socket.create_connection(address)
        self.sm_tasks = []
        self.buffers = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        for task in self.sm_tasks:
            task.exit_task()
        for buf in self.buffers:
            buf.free()
        return False

    def send(self, data):
        return self.c.sendall(data)

    def recv(self, size):
        return self.c.recv(size, socket.MSG_WAITALL)

    def cmd(self, cmd, buf = b''):
        self.send(struct.pack('<I', cmd) + buf)

    def recv_fmt(self, fmt):
        val = struct.unpack(fmt, self.recv(struct.calcsize(fmt)))
        if len(val) == 1: val = val[0]
        return val

    def close(self):
        self.cmd(0)

    def ping(self):
        self.cmd(1)
        return self.recv(5) == b'pong\0'

    def malloc(self, size):
        self.cmd(2, struct.pack('<2Q', 0, size))
        return self.recv_fmt('<Q')

    def free(self, addr):
        self.cmd(3, struct.pack('<3Q', 0, addr, 0))

    def malloc_contig(self, size):
        self.cmd(2, struct.pack('<2Q', 1, size))
        return self.recv_fmt('<Q')

    def free_contig(self, addr, size):
        self.cmd(3, struct.pack('<3Q', 1, addr, size))

    def call(self, rva, *args):
        num_args = len(args)
        if num_args > 10: raise Exception('too many args')
        args = list(args) + [0] * (10 - num_args)
        self.cmd(4, struct.pack('<QQ10Q', rva, num_args, *args))
        return self.recv_fmt('<Q')

    def mem_read(self, addr, size):
        self.cmd(5, struct.pack('<QQ', addr, size))
        return self.recv(size)

    def mem_read_fmt(self, fmt, addr):
        return struct.unpack(fmt, self.mem_read(addr, struct.calcsize(fmt)))[0]
    def mem_read_u8(self, addr):
        return self.mem_read_fmt('<B', addr)
    def mem_read_u32(self, addr):
        return self.mem_read_fmt('<I', addr)
    def mem_read_u64(self, addr):
        return self.mem_read_fmt('<Q', addr)
    def mem_read_str(self, addr, size, encoding='ascii', errors='ignore'):
        return self.mem_read(addr, size).rstrip(b'\0').decode(encoding, errors=errors)

    def mem_write(self, addr, buf):
        self.cmd(6, struct.pack('<QQ', addr, len(buf)) + buf)

    def mem_write_fmt(self, fmt, addr, val):
        self.mem_write(addr, struct.pack(fmt, val))
    def mem_write_u8(self, addr, val):
        self.mem_write_fmt('<B', addr, val)
    def mem_write_u32(self, addr, val):
        self.mem_write_fmt('<I', addr, val)
    def mem_write_u64(self, addr, val):
        self.mem_write_fmt('<Q', addr, val)

    def runtime_info(self):
        self.cmd(7)
        class RuntimeInfo:
            def __init__(self, arr):
                self.sdk_ver_ppr, self.kernel_base, self.sym_addr, self.sym_size = arr
        return RuntimeInfo(self.recv_fmt('<4Q'))

    def vtophys(self, va):
        self.cmd(8, struct.pack('<Q', va))
        return self.recv_fmt('<Q')

    def sblServiceRequest(self, hdr, req, poll=False):
        assert len(hdr) == 0x18
        self.cmd(9, hdr + struct.pack('<I', poll) + req)
        rv = self.recv_fmt('<i')
        if rv == 0x1337dead: return None, None
        resp_len = self.recv_fmt('<H')
        #print(hdr.hex(), req.hex(), f'resp_len {resp_len:x}')
        return rv, self.recv(resp_len)

    def smn_read(self, addr, size):
        size_aligned = align_up(size, 4)
        self.cmd(10, struct.pack('<3I', addr, size_aligned//4, 4))
        status = self.recv_fmt('<I')
        if status != 0: return None
        buf = self.recv(size_aligned)
        return buf[:size]

    def smn_read_noinc(self, addr, count):
        self.cmd(10, struct.pack('<3I', addr, count, 0))
        status = self.recv_fmt('<I')
        if status != 0: return None
        return self.recv(count * 4)

    def smn_read32(self, addr):
        return struct.unpack('<I', self.smn_read(addr, 4))[0]
    def smn_read64(self, addr):
        return struct.unpack('<Q', self.smn_read(addr, 8))[0]
    def smn_write32(self, addr, val):
        self.smn_write(addr, struct.pack('<I', val))
    def smn_write64(self, addr, val):
        self.smn_write(addr, struct.pack('<Q', val))

    def smn_write(self, addr, buf):
        size_aligned = align_up(len(buf), 4)
        self.cmd(11, struct.pack('<3I', addr, size_aligned//4, 4) + buf)
        status = self.recv_fmt('<I')
        return status == 0

    def mp4_read(self, addr, size):
        size_aligned = align_up(size, 4)
        self.cmd(12, struct.pack('<3I', addr, size_aligned//4, 4))
        status = self.recv_fmt('<I')
        if status != 0: return None
        buf = self.recv(size_aligned)
        return buf[:size]

    def mp4_write(self, addr, buf):
        size_aligned = align_up(len(buf), 4)
        self.cmd(13, struct.pack('<3I', addr, size_aligned//4, 4) + buf)
        status = self.recv_fmt('<I')
        return status == 0

    def df_read32(self, instance, function, offset):
        self.cmd(14, struct.pack('<5I', 0, instance, function, offset, 0))
        return self.recv_fmt('<I')

    def df_write32(self, instance, function, offset, val):
        self.cmd(14, struct.pack('<5I', 1, instance, function, offset, val))
        return self.recv_fmt('<I') == 0

    def brute_key_handle(self, handle_lo):
        self.cmd(15, struct.pack('<H', handle_lo))
        return self.recv_fmt('<I')

    def mp1_read(self, addr, size):
        size_aligned = align_up(size, 4)
        self.cmd(16, struct.pack('<2I', addr, size_aligned//4))
        status = self.recv_fmt('<I')
        if status != 0: return None
        buf = self.recv(size_aligned)
        return buf[:size]

    def mp1_write(self, addr, buf):
        size_aligned = align_up(len(buf), 4)
        self.cmd(17, struct.pack('<2I', addr, size_aligned//4) + buf)
        status = self.recv_fmt('<I')
        return status == 0

    def mp1_dump(self):
        self.cmd(18)
        status = self.recv_fmt('<I')
        if status != 0: return None
        return self.recv(0x40000)

    def vn_rw(self, path, offset, size):
        path = bytes(path, 'ascii')
        flags = 1 # FREAD
        self.cmd(19, struct.pack('<BHiiQ', 0, len(path), flags, size, offset) + path)
        status, resid = self.recv_fmt('<Iq')
        print(f'vn_rw {status:8x} {resid}')
        if status != 0: return None
        return self.recv(size)

    def sceSblServiceMailbox(self, handle, func_id, mail=b''):
        mail = struct.pack('<HHi', func_id, 0, 0) + mail
        if len(mail) > 0x80: raise Exception('mail too big')
        mail = mail.ljust(0x80, b'\0')
        hdr = make_svc_mail_hdr(handle)
        rv, resp = self.sblServiceRequest(hdr, mail)
        if rv != 0:
            pass#print('sceSblServiceMailbox: %d' % rv)
        return rv, resp

    def sceSblServiceSpawn(self, name):
        req = struct.pack('<Q4I8sQ', 0, 0, 0, 0, 0, bytes(name, 'ascii'), 0)
        assert len(req) == 0x28, hex(len(req))
        rv, resp = self.sblServiceRequest(make_sys_mail_hdr(0x28, 0x8, 1), req)
        if rv != 0:
            print('sceSblServiceSpawn: %d' % rv)
        else:
            return struct.unpack('<Q', resp)[0]

    def sceSblServiceWaitForExit(self, handle):
        hdr = make_sys_mail_hdr(0x10, 0, 1)
        req = struct.pack('<2Q', 1, handle)
        return self.sblServiceRequest(hdr, req)

    def sceSblServiceClose(self, handle):
        rv, resp = self.sceSblServiceMailbox(handle, 0xffff)
        if rv != 0:
            print('sceSblServiceExit: %d' % rv)
        return self.sceSblServiceWaitForExit(handle)

    class SmTask:
        def __init__(self, client, name, handle):
            self.client = client
            self.name, self.handle = name, handle
        def __del__(self):
            self.exit_task()
        def exit_task(self):
            if self.handle is not None:
                print(f'exiting {self.name} {self.handle}')
                self.client.sceSblServiceClose(self.handle)
            self.handle = None

    def sm_spawn(self, name):
        handle = self.sceSblServiceSpawn(name)
        print(f'spawn {name} {handle}')
        if handle is None: return None
        self.sm_tasks.append(self.SmTask(self, name, handle))
        return handle

    class RemoteBuffer:
        def __init__(self, size, client):
            self.client = client
            self.size = size
            self.contig = True
            self.va = self.client.malloc_contig(self.size)
            if self.va == 0:
                self.contig = False
                self.va = self.client.malloc(self.size)
            assert self.va != 0
            self.pa = None
            #print(f'remotebuf alloc {self.va:x} {self.contig}')
        def __del__(self):
            self.free()
        def free(self):
            if self.va is None: return
            #print(f'remotebuf free {self.va:x}')
            if self.contig:
                self.client.free_contig(self.va, self.size)
            else:
                self.client.free(self.va)
            self.va = None
        def is_contig(self): return self.contig
        def get_va(self): return self.va
        def get_pa(self):
            if self.pa is None:
                self.pa = self.client.vtophys(self.va)
            return self.pa
        def read(self, size=None):
            if size is None:
                size = self.size
            return self.client.mem_read(self.va, size)
        def write(self, buf):
            self.client.mem_write(self.va, buf)

    def buffer_alloc(self, size):
        buf = self.RemoteBuffer(size, self)
        self.buffers.append(buf)
        return buf
    def buffer_free(self, buf):
        self.buffers.remove(buf)

class Dmap:
    def __init__(self, client: Client):
        self.client = client
        # this mapping is created by kpayload
        self.base = 0xffffffe000000000
    def read(self, pa, size):
        return self.client.mem_read(self.base | pa, size)
    def read_u8(self, pa):
        return self.client.mem_read_u8(self.base | pa)
    def read_u32(self, pa):
        return self.client.mem_read_u32(self.base | pa)
    def read_u64(self, pa):
        return self.client.mem_read_u64(self.base | pa)
    def write(self, pa, buf):
        self.client.mem_write(self.base | pa, buf)
    def write_u8(self, pa, val):
        self.client.mem_write_u8(self.base | pa, val)
    def write_u32(self, pa, val):
        self.client.mem_write_u32(self.base | pa, val)
    def write_u64(self, pa, val):
        self.client.mem_write_u64(self.base | pa, val)

class TmrAccess:
    class Tmr:
        def __init__(self, base, limit, ctl, requestors):
            self.base, self.limit, self.ctl, self.requestors = base, limit, ctl, requestors
    def __init__(self, client):
        self.client = client
        self.dmap = Dmap(self.client)
        self.ind_index = pci_cfg_addr(0, 0x18, 2, 0x80)
        self.ind_data = self.ind_index + 4
    def read32(self, addr):
        self.dmap.write_u32(self.ind_index, addr)
        return self.dmap.read_u32(self.ind_data)
    def write32(self, addr, val):
        self.dmap.write_u32(self.ind_index, addr)
        self.dmap.write_u32(self.ind_data, val)
    def read(self, index):
        return self.Tmr(*[self.read32(index * 0x10 + i * 4) for i in range(4)])

def mp4_setup_tlb(client, tlb_index, addr):
    assert tlb_index >= 4, 'dont overwrite used tlbs plz'
    assert tlb_index < 32, 'tlb oob'

    tlb_addr = 0x03220000 + (tlb_index // 2) * 4
    tlb_shift = (tlb_index % 2) * 16

    tlb = struct.unpack('<I', client.mp4_read(tlb_addr, 4))[0]
    tlb = (tlb & ~(0xffff << tlb_shift)) | ((addr >> 20) << tlb_shift)
    client.mp4_write(tlb_addr, struct.pack('<I', tlb))

    mp_axi_addr = 0x01000000 + 0x100000 * tlb_index
    offset = addr & ((1 << 20) - 1)
    return mp_axi_addr + offset

def all_zero(x): return all(map(lambda x: x == 0, x))
def all_ff(x): return all(map(lambda x: x == 0xff, x))

def send_psp_cmd(client, cmd_id, msg):
    status_reg_prev, addr_reg_prev = struct.unpack('<IQ', client.smn_read(0x03800000 + 0x10570, 0xc))
    cmd = cmd_id << 16
    #msg.write(b'\xff'*PAGE_SIZE)

    client.smn_write(0x03800000 + 0x10570 + 4, struct.pack('<Q', msg.get_pa()))
    #client.smn_write(0x03800000 + 0x10570 + 4, struct.pack('<Q', 0xffffffffffffffff))
    #client.smn_write(0x03800000 + 0x10570 + 4, struct.pack('<Q', 0))
    client.smn_write(0x03800000 + 0x10570, struct.pack('<I', cmd))
    for i in range(10):
        status_reg, addr_reg = struct.unpack('<IQ', client.smn_read(0x03800000 + 0x10570, 0xc))
        if ((status_reg >> 16) & 0xff) == 0:
            break
    buf = msg.read(0x100)
    if (not all_zero(buf)) or status_reg != 0x80000004:
        print(f'prev {status_reg_prev:x} {addr_reg_prev:x}')
        hexdump(buf)
        print(f'{status_reg:x} {addr_reg:x}')

def iter_procs(c: Client):
    # 3.00 struct proclist allproc
    proc = c.runtime_info().kernel_base + 0x333dc58
    while proc != 0:
        pid = c.mem_read_u32(proc + 0xbc)
        title = c.mem_read_str(proc + 0x470, 10)
        name = c.mem_read_str(proc + 0x59c, 0x20)
        if name == 'eboot.bin':
            name = title + '_' + name
        name = name.replace('.', '_').replace('-', '_')
        yield pid, proc, name
        proc = c.mem_read_u64(proc + 0)

def proc_va2pa(c, proc, addr):
    if addr >= (1<<47):
        raise Exception('get a grip bro')
    vmspace = c.mem_read_u64(proc + 0x200)
    #print('vmspace %x' % vmspace)
    pml4 = c.mem_read_u64(vmspace + 0x308) # == 0
    #print('pml4 %x' % pml4)
    dmap = Dmap(c)
    pml4e = dmap.read_u64(pml4 + 8*((addr >> 39) & 0x1ff))
    #print('pml4e %x' % pml4e)
    if not (pml4e & 1):
        raise Exception('pml4e not present bro')
    pml3 = pml4e & 0xFFFFFFFF000
    pml3e = dmap.read_u64(pml3 + 8*((addr >> 30) & 0x1ff))
    #print('pml3e %x' % pml3e)
    if not (pml3e & 1):
        raise Exception('pml3e not present bro')
    if pml3e & 0x80:
        align = (1<<30)-1
        return (pml3e & 0xFFFFFFFF000) + (addr & align)
    pml2 = pml3e & 0xFFFFFFFF000
    pml2e = dmap.read_u64(pml2 + 8*((addr >> 21) & 0x1ff))
    #print('pml2e %x' % pml3e)
    if not (pml2e & 1):
        raise Exception('pml2e not present bro')
    if pml2e & 0x80:
        align = (1<<21)-1
        return (pml2e & 0xFFFFFFFF000) + (addr & align)
    pml1 = pml2e & 0xFFFFFFFF000
    pte = dmap.read_u64(pml1 + 8*((addr >> 12) & 0x1ff))
    #print('pte %x' % pte)
    if not (pte & 1):
        raise Exception('pte not present bro')
    align = (1<<12)-1
    return (pte & 0xFFFFFFFF000) + (addr & align)

def proc_r64(c, proc, addr):
    dmap = Dmap(c)
    return dmap.read_u64(proc_va2pa(c, proc, addr))

def proc_w64(c, proc, addr, value):
    dmap = Dmap(c)
    dmap.write_u64(proc_va2pa(c, proc, addr), value)

def proc_r(c, proc, addr, size):
    dmap = Dmap(c)
    return dmap.read(proc_va2pa(c, proc, addr), size)

def proc_w(c, proc, addr, value):
    dmap = Dmap(c)
    dmap.write(proc_va2pa(c, proc, addr), value)

def dump_va_for_process(c, proc):
    vmspace = c.mem_read_u64(proc + 0x200)
    print('vmspace %x' % vmspace)
    pml4 = c.mem_read_u64(vmspace + 0x308) # == 0
    print('pml4 %x' % pml4)
    dmap = Dmap(c)

    def store_dump(va, pa, incr):
        dir = 'raw_dump'
        os.makedirs(dir, exist_ok=True)
        open(dir + ('/%016x.bin' % va), 'wb').write(dmap.read(pa, incr))

    def dump_pml(maps, va, pml, level):
        incr = 1 << (12 + 9*(level-1))
        print('level', level)

        for i in range(0x200):
            if level==4 and i>=0x100: # skip kernel
                continue

            #print('dmap reading %x' % (pml + 8*i))
            pte = dmap.read_u64(pml + 8*i)
            #print('dmap read complete')

            pa = pte & 0xFFFFFFF000
            #print('pte=%x' % pte)

            #       pa=3e8a51000
            #if pa >= 0x100000000: #0x3e8000000:
            #    print('IGNORING %016x %016x %016x' % (va, pa, pte))
            #    va += incr
            #    continue

            if (pte & 1) == 0: # not present?
                va += incr
                continue

            if level == 1:
                #maps += [ (va, pa, incr) ]
                print('adding smol mapping')
                store_dump(va, pa, incr)
            else:
                if pte & (1<<7): # large page
                    print('adding mapping')
                    store_dump(va, pa, incr)
                    #maps += [ (va, pa, incr) ]
                else:
                    dump_pml(maps, va, pa, level-1)

            va += incr
            #print('%x' % va)

        print('done')

    # 3.00 proc0
    #        local proc_pid = kr64(proc + 0xbc).lo
    #        local proc_vmspace = kr64(proc + 0x200)
    #        local proc_pml4_pa = kr64(proc_vmspace + 0x308)
    maps = []
    dump_pml(maps, 0, pml4, 4)
    for m in maps:
        print(hex(m[0]), hex(m[1]))

class NvmeCtl:
    def __init__(self, client: Client, scratch_gva, scratch_pa):
        self.client = client
        self.scratch_gva = scratch_gva
        self.scratch_pa = scratch_pa
        self.dmap = Dmap(self.client)

        ri = self.client.runtime_info()
        assert ri.sdk_ver_ppr == 0x300003800000001

        self.rva_a53io_scf_direct_cmd = 0x3a4420
        self.rva_nvme_sc = 0x31ced18
        nvme_sc = self.client.mem_read_u64(ri.kernel_base + self.rva_nvme_sc)
        assert nvme_sc != 0

        # "buf_info" is just DW15..DW10 (per-cmd defined)
        self.buf_info = self.client.buffer_alloc(0x18)

    def dump_scratch(self):
        hexdump(self.dmap.read(self.scratch_pa, 0x200))

    def _write_buf_info(self, w12, w13, w14, w15):
        self.buf_info.write(struct.pack('<6I', 0, 0, w12, w13, w14, w15))

    def scf_direct_cmd(self, qid, ocid, opc, nsid, dma_addr, w12, w13=0, w14=0, w15=0):
        # a53io_scf_direct_cmd uses qid==0 to mean admin queue, otherwise subtracts 1
        # there's actually just 2*num_cpus queues, anything above that just gets mapped onto some existing queue
        assert 0 <= qid < 9
        assert 0 <= ocid < 768
        # ?
        assert 0 <= nsid < 4
        # gva mapped for pcie device 40.0.0 (range is 0x50000000:0x53200000)
        # ...it's not constant? :/
        #assert 0x51000000 <= dma_addr < 0x53200000
        self._write_buf_info(w12, w13, w14, w15)
        # a wrapper for nvme_io_vsc
        return self.client.call(self.rva_a53io_scf_direct_cmd,
            qid, ocid, opc, nsid, dma_addr, self.buf_info.get_va())

    def set_nand_eval_mode(self, enable):
        # DW13 = enable
        return self.scf_direct_cmd(0, 0, 0xc4, 0, self.scratch_gva, 0x38, enable)

    def set_debug_log(self, enable):
        return self.scf_direct_cmd(0, 0, 0xc8, 0, self.scratch_gva, 0x62, enable)

    def _read_physical_page(self, sram_sector):
        # ???
        w12 = (0 << 4) | 0
        return self.scf_direct_cmd(1, 0, 0xd0, 0, self.scratch_gva, w12, 0, sram_sector)

    def _read_sram(self, sector, num_sectors):
        assert num_sectors < 0x80
        return self.scf_direct_cmd(1, 0, 0x92, 0, self.scratch_gva, num_sectors - 1, 0, sector)

    def _read_dram(self, sector, num_sectors):
        return self.scf_direct_cmd(1, 0, 0x9a, 0, self.scratch_gva, num_sectors - 1, 0, sector)

    def _write_dram(self, sector, num_sectors):
        return self.scf_direct_cmd(1, 0, 0x9d, 0, self.scratch_gva, num_sectors - 1, 0, sector)

    def _vsc_admin_c4_40(self):
        return self.scf_direct_cmd(0, 0, 0xc4, 0, self.scratch_gva, 0x40, 0, 0, 0)

    def _vsc_admin_c4_43(self):
        return self.scf_direct_cmd(0, 0, 0xc4, 0, self.scratch_gva, 0x43, 0, 0, 0)

    def read_sram(self):
        # the sram is repeating <0x10600 bytes><0x10608 bytes> buffers, where the 0x10600 byte
        # one is actively being updated. maybe this is 0x80 * (0x200 + 0xc) raw sector data?
        # probably explains why > 0x80 sectors at once causes it to die, too.
        data = b''
        for sector in range(0xc60):
            self._read_sram(sector, 1)
            data += self.dmap.read(self.scratch_pa, 0x200)
        return data

    def read_physical_page(self):
        sram_offset = 0x180000
        sram_sector = sram_offset // 0x200
        self._read_physical_page(sram_sector)
        data = b''
        for i in range(0x5000 // 0x200):
            self._read_sram(sram_sector + i, 1)
            data += self.dmap.read(self.scratch_pa, 0x200)
        return data

if __name__ == '__main__':
    with Client() as c:
        '''
        msg = c.buffer_alloc(PAGE_SIZE)
        # somethings seems to be at [0x70,0x75]
        tmr_id, addr, size = 1, 0, 0x10000
        msg.write(struct.pack('<IIIIQQ', 0x20, 0, tmr_id, 0, addr, size))
        send_psp_cmd(c, 0x75, msg)
        '''

        nvme = NvmeCtl(c, 0x53000000, 0x1af10000)
        dmap = Dmap(c)
        ddr_size = 1 << 29
        addr = 0x404D7ABA
        ddr_offset = addr & (ddr_size - 1)
        sector_offset = ddr_offset & 0x1ff
        sc = open('kpayload/efc_shellcode', 'rb').read()
        nvme._read_dram((ddr_size + ddr_offset)//0x200, 0x200//0x200)
        assert len(sc) <= 0x200 - sector_offset
        dmap.write(nvme.scratch_pa + sector_offset, sc)
        nvme._write_dram((ddr_size + ddr_offset)//0x200, 0x200//0x200)
        nvme._vsc_admin_c4_43()
        exit()

        #with open('nvme_ddr_dump2.bin', 'wb') as f:
        #    chunk_size = 0x200 * 64
        #    for i in range(0, 0x600000, chunk_size):
        #        nvme._read_dram((0x20000000 + i)//0x200, chunk_size//0x200)
        #        data = dmap.read(nvme.scratch_pa, chunk_size)
        #        f.write(data)
        #        f.flush()
        #exit()

        # doesnt work...because of arm cache?
        #ret0 = 0x04390|1
        #ddr_offset = 0x4C0EB4
        #sector_offset = ddr_offset & 0x1ff
        #nvme._read_dram((0x20000000 + ddr_offset)//0x200, 0x200//0x200)
        #orig = dmap.read_u32(nvme.scratch_pa + sector_offset)
        #assert orig == 0x8454|1
        #print(f'orig {orig:x}')
        #dmap.write_u32(nvme.scratch_pa + sector_offset, ret0)
        #nvme._write_dram((0x20000000 + ddr_offset)//0x200, 0x200//0x200)
        #nvme._read_dram((0x20000000 + ddr_offset)//0x200, 0x200//0x200)
        #buf = dmap.read(nvme.scratch_pa, 0x200)
        #open(f'nvme_dump.bin', 'wb').write(buf)
        #exit()

        #hexdump(Dmap(c).read(0, 0x1000))
        #print('{'+','.join([f'{name}={pid}' for pid, name in iter_procs(c)]) + '}')

        dmap = Dmap(c)
        dev_table_pa = c.smn_read64(0x2400000)
        dev_table_pa &= ~((1 << 12) - 1)
        print(f'{dev_table_pa:x}')
        dev_table = dmap.read(dev_table_pa, (0x1ff + 1) * 0x1000)
        #open('iommu_dev_table.bin', 'wb').write(dev_table)

        iommu_ctrl = c.smn_read64(0x2400000 + 0x18)
        iommu_efr = c.smn_read64(0x2400000 + 0x30)
        gten = (iommu_ctrl >> 16) & 1
        gtsup = (iommu_efr >> 4) & 1
        glxsup = (iommu_efr >> 14) & 3
        # 1 level also needs DTE.{GV=1,GLX=0}..they all seem to have that
        # this means there is a single level/page indexed by PASID before the actual page table
        one_lvl_gcr3 = gten == 1 and gtsup == 1 and glxsup == 1
        if not one_lvl_gcr3:
            print(f'{iommu_ctrl:x} (GTEn {gten}) {iommu_efr:x} (GTSup {gtsup} GLXSup {glxsup})')

        #'''
        for i in range(0, len(dev_table), 0x20):
            dte = int.from_bytes(dev_table[i:i+0x20], 'little')
            if (dte & 3) != 3: continue
            had = (dte >> 7) & 0b11
            mode = (dte >> 9) & 0b111
            ptrp = (dte >> 12) & ((1 << 40) - 1)
            ptrp <<= 12
            gprp = (dte >> 53) & 1
            giov = (dte >> 54) & 1
            gv = (dte >> 55) & 1
            glx = (dte >> 56) & 0b11
            gcr3_trp_l = (dte >> 58) & 0b111
            gcr3_trp_m = (dte >> 80) & 0xffff
            I = (dte >> 96) & 1
            ioctl = (dte >> 99) & 0b11
            ex = (dte >> 103) & 1
            sys_mgt = (dte >> 104) & 0b11
            sats = (dte >> 106) & 1
            gcr3_trp_h = (dte >> 107) & ((1 << 21) - 1)
            gcr3_trp = (gcr3_trp_h << 31) | (gcr3_trp_m << 15) | (gcr3_trp_l << 12)
            iv = (dte >> 128) & 1
            intctl = (dte >> 188) & 0b11
            idx = i//0x20
            bus = idx >> 8
            dev = (idx >> 3) & 0x1f
            func = idx & 7
            addr_str = f'{bus:x}.{dev}.{func}'
            print(f'{i:8x}[{addr_str}] {dte:x} EX:{ex:x} ioctl:{ioctl:x} I:{I:x} gcr3_trp:{gcr3_trp:x} glx:{glx:x} gv:{gv:x} giov:{giov:x} gprp:{gprp:x} ptrp:{ptrp:x} mode:{mode:x} had:{had:x}')

            # alredy checked valid bits
            gcr3_l1 = dmap.read(gcr3_trp, 0x1000)
            #open(f'iommu_{addr_str}_gcr3_l1.bin', 'wb').write(gcr3_l1)
            for gi in range(0, 0x200, 8):
                gcr3 = int.from_bytes(gcr3_l1[gi:gi+8], 'little')
                if (gcr3 & 1) == 0: continue
                print(f'pasid {gi//8} cr3 {gcr3:x}')

            if addr_str == '40.0.0':
                pasid0 = dmap.read_u64(gcr3_trp)
                print(f'pasid0 {pasid0:x}')
                pasid0 &= ~0xfff
                for lvl4i in range(0x200):
                    lvl4e = dmap.read_u64(pasid0 + lvl4i * 8)
                    if (lvl4e & 1) == 0: continue
                    print(f'4 {lvl4i:3x} {lvl4e:16x}')
                    lvl4e &= 0xf_ffff_ffff_f000
                    for lvl3i in range(0x200):
                        lvl3e = dmap.read_u64(lvl4e + lvl3i * 8)
                        if (lvl3e & 1) == 0: continue
                        print(f'3 {lvl3i:3x} {lvl3e:16x}')
                        lvl3e &= 0xf_ffff_ffff_f000
                        for lvl2i in range(0x200):
                            lvl2e = dmap.read_u64(lvl3e + lvl2i * 8)
                            if (lvl2e & 1) == 0: continue
                            print(f'2 {lvl2i:3x} {lvl2e:16x}')
                            lvl2e &= 0xf_ffff_ffff_f000
                            for lvl1i in range(0x200):
                                lvl1e = dmap.read_u64(lvl2e + lvl1i * 8)
                                va = (lvl4i << 39) | (lvl3i << 30) | (lvl2i << 21) | (lvl1i << 12)
                                if lvl1e == 0: continue
                                pa = lvl1e & 0xf_ffff_ffff_f000
                                print(f'va {va:16x} pte {lvl1e:16x} pa {pa:16x}')
                                if (lvl1e & 1) == 0: continue
                                print(f'1 {lvl1i:3x} {lvl1e:16x}')
                                lvl1e &= 0xf_ffff_ffff_f000
        #'''
        #open('nvme_cmd_resp.bin', 'wb').write(dmap.read(0x43da58000, 0x5000))
        exit()

        # set EX=1 for B40D00F00
        dte_pa = dev_table_pa + 0x20 * (0x40 << 8)
        nvme_dte = int.from_bytes(dmap.read(dte_pa, 0x20), 'little')
        nvme_dte |= 1 << 103
        dmap.write(dte_pa, nvme_dte.to_bytes(0x20, 'little'))

        # invalidate_devtab_entry
        kernel_base = c.runtime_info().kernel_base
        iommu_sc = c.mem_read_u64(kernel_base + 0x425d718)
        cmd = c.buffer_alloc(0x10)
        device_id = 0x4000
        cmd.write(struct.pack('<HHI', device_id, 0, 2 << 28))
        c.call(0x4a9dd0, iommu_sc, cmd.get_va())
        c.buffer_free(cmd)

        #c.close()