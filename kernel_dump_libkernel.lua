local lk_module_list = mods.lk + 0x78270
local modlist_count = r64(lk_module_list - 8).lo

function handle_from_lk_index(index)
    return r32(lk_module_list + 0x98 * index + 0x10)
end

function text_size_from_lk_index(index)
    return r32(lk_module_list + 0x98 * index + 0x50)
end

function data_base_from_lk_index(index)
    return r64(lk_module_list + 0x98 * index + 0x58)
end

function data_size_from_lk_index(index)
    return r32(lk_module_list + 0x98 * index + 0x60)
end

syscalls = {
    fstat = 189,
    mmap = 477,
    rtprio = 166,
    yield = 321,
    sched_yield = 331,
    thr_exit = 431,
    _umtx_op = 454,
    thr_new = 455,
    ftruncate = 480,
    rtprio_thread = 466,
    sched_getscheduler = 330,
    sched_setscheduler = 329,
    cpuset_getaffinity = 487,
    cpuset_setaffinity = 488,
    shm_open = 482,
    ioctl = 54,
    setuid = 23,
    mprotect = 74,
    munmap = 73,
    kqueue = 362,
    kevent = 363,
    dup = 41,
    lseek = 478,
    dynlib_dlopen = 589,
    dynlib_dlclose = 590,
    dynlib_dlsym = 591,
    dynlib_get_list = 592,
    dynlib_get_info = 593,
    dynlib_load_prx = 594,
    dynlib_unload_prx = 595,
    dynlib_do_copy_relocations = 596,
    dynlib_prepare_dlclose = 597,
    dynlib_get_proc_param = 598,
    dynlib_process_needed_and_relocate = 599,
    dynlib_get_info_ex = 608,
    dynlib_get_obj_member = 649,
    dynlib_get_info_for_libdbg = 656,
    dynlib_get_list2 = 659,
    dynlib_get_info2 = 660,
    dynlib_get_list_for_libdbg = 672,
    setsid = 147,
    sendfile = 393,
    socketpair = 135,
    readv = 120,
    pread = 475,
    setsockopt = 105,
    nanosleep = 240,
    recv = 102,
    recvfrom = 29,
    sendto = 133
}

--kdata_base = kernel_data_base + 0x4000
--kernel_text_base = kdata_base - 0x1b80000

function cr3_by_pid(pid)
    local proc = kproc
    while true do
        local proc_pid = kr64(proc + 0xbc).lo
        if proc_pid == pid then
            local proc_vmspace = kr64(proc + 0x200)
            local proc_pml4_pa = kr64(proc_vmspace + 0x308)
            return proc_pml4_pa
        end
        proc = kr64(proc)
        if proc:is_zero() then
            return nil
        end
    end
end

local pcie_cfg_base = Uint64:new(0xF0000000)

function pci_addr(b, d, f)
    return pcie_cfg_base + b * 0x100000 + d * 0x8000 + f * 0x1000
end

local tmr_indirect = pci_addr(0, 0x18, 2)
function tmr_read32(addr)
    pw32(tmr_indirect + 0x80, addr)
    return pr32(tmr_indirect + 0x84)
end

function tmr_write32(addr, val)
    pw32(tmr_indirect + 0x80, addr)
    pw32(tmr_indirect + 0x84, val)
end

function tmr_read(index)
    local addr = index * 0x10
    return {
        base = tmr_read32(addr),
        limit = tmr_read32(addr + 4),
        cfg = tmr_read32(addr + 8),
        requestors = tmr_read32(addr + 12),
    }
end

function tmr_add_for_all(base, limit)
    local index = 21
    local addr = index * 0x10
    tmr_write32(addr + 8, 0)
    tmr_write32(addr + 0, base)
    tmr_write32(addr + 4, limit)
    tmr_write32(addr + 12, 0)
    tmr_write32(addr + 8, 0x3f07)
end

local b0d0f0 = pci_addr(0, 0, 0)

function smn_read32(addr)
    pw32(b0d0f0 + 0x60, addr)
    return pr32(b0d0f0 + 0x64)
end

function smn_write32(addr, val)
    pw32(b0d0f0 + 0x60, addr)
    pw32(b0d0f0 + 0x64, val)
end

function smn_read64(addr)
    return Uint64:new(smn_read32(addr).lo, smn_read32(addr + 4).lo)
end

function smn_write64(addr, val)
    val = force_Uint64(val)
    smn_write32(addr, val.lo)
    smn_write32(addr + 4, val.hi)
end

local iommu_addr = 0x2400000
function set_exclusion(base, size)
    -- [51:12] base, [1] allow, [0] enable
    smn_write64(iommu_addr + 0x20, base)
    -- [51:12] limit
    smn_write64(iommu_addr + 0x28, base + size - 1)
    smn_write64(iommu_addr + 0x20, base + 3)
end

function get_exclusion()
    return {
        base = smn_read64(iommu_addr + 0x20),
        limit = smn_read64(iommu_addr + 0x28),
    }
end

--[[
for i=0, 20, 1 do
    local tmr = tmr_read(i)
    log(string.format('tmr %2d ', i)..tostring(tmr.base)..' '..tostring(tmr.limit)..' '..tostring(tmr.cfg)..' '..tostring(tmr.requestors))
end

log('modlist_count '..tostring(modlist_count))

-- skip idx 0 (eboot)
for i=0, modlist_count, 1 do
    local handle = handle_from_lk_index(i).lo
    if handle == 0xffffffff then
        log('got -1 handle')
        break
    end
    local text_base = text_base_from_lk_index(i)
    local text_size = text_size_from_lk_index(i).lo
    --local data_end = data_base_from_lk_index(i) + data_size_from_lk_index(i)
    --local size = data_end - text_base
    local logstr = { 'module '..i }
    for pos = 0, text_size-0x1000, 0x1000 do
        local page = text_base + pos
        local pte_pa, pte = get_pte_ptr(page)
        table.insert(logstr, string.format('%08x', pos)..' '..tostring(pte_pa)..' '..tostring(pte))
    end
    log(table.concat(logstr, '\n'))
end

collectgarbage()
--]]
--[[
local logstr = { 'kernel' }
for pos = 0, 0x82d0000, 0x1000 do
    local page = kernel_text_base + pos
    local pte_pa, pte = get_pte_ptr(page)
    table.insert(logstr, tostring(page)..string.format(' %08x', pos)..' '..tostring(pte_pa)..' '..tostring(pte))
end
log(table.concat(logstr, '\n'))
--]]
--[[
local page = text_base_from_lk_index(1)
local pte_pa, pte = get_pte_ptr(page)
if pte.hi == 0x04000000 then
    pte.hi = 0
    pw64(pte_pa, pte)
end
tcp_file_write('lk_page', r(page, 0x1000))
--]]

function dynlib_load_prx(name)
    local p_handle = malloc(0x100)
    -- ?
    local flags = 0
    local rv = call(sym.syscall, syscalls.dynlib_load_prx, c_str(name), flags, p_handle)
    local handle = r32(p_handle).lo
    free(p_handle)
    if rv:negative_s64() then
        log_err('dynlib_load_prx')
        return nil
    end
    return handle
end

function dynlib_unload_prx(handle)
    local rv = call(sym.syscall, syscalls.dynlib_unload_prx, handle)
    if rv:negative_s64() then
        log_err('dynlib_unload_prx')
        return false
    end
    return true
end

function dynlib_get_list()
    local num_handles = 100
    local scratch = malloc(num_handles * 4)
    local p_num_handles = scratch
    local p_handles = scratch + 8
    local rv = call(sym.syscall, syscalls.dynlib_get_list, p_handles, num_handles, p_num_handles)
    local handles = {}
    if rv:is_zero() then
        local num_handles = r64(p_num_handles).lo
        for i=0,num_handles-1,1 do
            table.insert(handles, r32(p_handles + 4 * i).lo)
        end
    end
    free(scratch)
    return handles
end

function dynlib_dlsym(handle, name, p_addr)
    return call(sym.syscall, syscalls.dynlib_dlsym, handle, name, p_addr)
end

function parse_info_ex(info_ex)
    local name_raw = r(info_ex + 8, 0x100)
    local name_end = name_raw:find(string.char(0))
    if name_end then name_raw = name_raw:sub(1, name_end - 1) end
    return {
        name = name_raw,
        handle = r32(info_ex + 0x108).lo,
        text_base = r64(info_ex + 0x160),
        text_size = r32(info_ex + 0x168),
        text_prot = r32(info_ex + 0x16c),
        data_base = r64(info_ex + 0x170),
        data_size = r32(info_ex + 0x178),
        data_prot = r32(info_ex + 0x17c),
        refcount = r32(info_ex + 0x1a4),
    }
end

function dynlib_get_info_ex(handle)
    local info_ex_sizeof = 0x1a8
    local info_ex = malloc(info_ex_sizeof)
    memcpy(info_ex, ub8(info_ex_sizeof), 8)
    -- bit0: ORs something into tls_index. bit1: censors module name
    local flags = 0
    local rv = call(sym.syscall, syscalls.dynlib_get_info_ex, handle, flags, info_ex)
    local info_ex_ = nil
    if rv:is_zero() then info_ex_ = parse_info_ex(info_ex) end
    if info_ex_ then
        log(info_ex_.name..' handle '..handle)
        log(string.tohex(r(info_ex, info_ex_sizeof)))
    end
    free(info_ex)
    return info_ex_
end

--[[]]
local mod_handles = dynlib_get_list()
log('num_handles '..#mod_handles)
local infos = {}
for k, handle in ipairs(mod_handles) do
    local info = dynlib_get_info_ex(handle)
    if info then table.insert(infos, info) else log('failed to get info for '..handle) end
    local data_end = info.data_base + info.data_size
    log(tostring(info.text_base)..' '..tostring(data_end)..' '..info.name..' '..handle)
    collectgarbage()
end
error('done')
--]]

--[[
local handle = dynlib_load_prx('libSceTextToSpeech2.sprx')
if handle then
    log('loaded')
    local info = dynlib_get_info_ex(handle)
    if info then
        local pte_pa, pte = get_pte_ptr(info.text_base)
        local pte_pa_kern, pte_kern = get_pte_ptr(kernel_text_base)
        local kern_pa = get_pa(kernel_text_base)
        local user_pa = get_pa(info.text_base)
        -- 0xb1cbf0
        if pte.hi == 0x04000000 then
            pte.hi = 0
            pw64(pte_pa, pte)
        end
        tcp_file_write('lk_page', r(info.text_base, 0x1000))
        log(tostring(info.text_base)..' '..tostring(pte))
        log(tostring(kernel_text_base)..' '..tostring(pte_kern))

        kern_pa = kern_pa + 5 + 0xb1c000
        kern_pa.hi = 0x04000000
        pw64(pte_pa, kern_pa)
        --tcp_file_write('lk_page2', r(info.text_base, 0x1000))
        call(info.text_base + 0xbf0)

        log('done')
    end
end
--]]

--[[]]
local exclusion = get_exclusion()
if exclusion.base.lo ~=3 then
    set_exclusion(0, Uint64:new(0xffffffff, 0xffffffff))
    exclusion = get_exclusion()
end
if exclusion.base.lo ~=3 then
    log('set exclusion failed '..tostring(exclusion.base)..' '..tostring(exclusion.limit))
end
--]]

-- a version-agnostic way to get the msgbuf physaddr
local psp_bar2 = dmap + Uint64:new(0xe0500000)
local sbl_msg_buf_pa = kr64(psp_bar2 + 0x10568)
sbl_msg_buf_pa = sbl_msg_buf_pa - (sbl_msg_buf_pa.lo % 0x10000)

-- maybe can just hardcode kms handle to 5
local kms_handle = 5 --kr64(kernel_text_base + 0x249c350) -- offset for 2.20

function psp_send_msg(cmd, buf_pa)
    -- write msg pa
    kw64(psp_bar2 + 0x10568, buf_pa)
    -- write trigger...would be nice to have 32bit writes!
    kw64(psp_bar2 + 0x10564, Uint64:new(cmd * 0x100, buf_pa.lo))
end

function psp_wait_result()
    local timeout = 50
    while timeout > 0 do
        local regs = kr64(psp_bar2 + 0x10564)
        local lobits = bitfield_extract(regs, 0, 2).lo
        if lobits == 1 then
            return true
        elseif lobits > 1 then
            return false
        end
        timeout = timeout - 1
    end
    log('psp_wait_result timeout')
    return false
end

-- doesn't seem to work (maybe only sysmail?)
function psp_send_msg_polled(cmd, buf_pa)
    -- write msg pa
    kw64(psp_bar2 + 0x10550, buf_pa)
    -- write trigger...would be nice to have 32bit writes!
    kw64(psp_bar2 + 0x1054c, Uint64:new(cmd * 0x100, buf_pa.lo))
    -- should wait for [0x1054c] bit0 to be set, and check bit1 for error
end

ub2 = function(x)
    local b0 = x % 256; x = (x - b0) / 256
    local b1 = x % 256
    return string.char(b0, b1)
end

function make_cmd_hdr(cmd, send_len, resp_len)
    return ub4(cmd)..ub2(send_len)..ub2(resp_len)..
        ub8(0) -- mid
end

function make_sys_mail_hdr(send_len, resp_len, handle)
    return make_cmd_hdr(5, send_len, resp_len)..ub8(handle)
end

function make_svc_mail_hdr(handle, func_id)
    return make_cmd_hdr(6, 0x80, 0x80) ..
        ub8(handle) ..
        ub2(func_id) ..
        string.rep(string.char(0), 6)
end

function pr(paddr, len)
    return r(Uint64:new(paddr.lo, paddr.hi + 0x60), len)
end

local sm_service_ctx = kernel_text_base + 0x47f97e0
-- we want to atomically (lol) set a bit in here
-- The bitpos to set is the index of the stolen req_ctx
local sm_service_bitmap0 = sm_service_ctx + 0x260
-- The index isn't important (doesn't need to match msg_buf index - msg
-- is matched to req based on mid), but higher indices are less likely
-- be used by other code. We may want custom mid(s), tho
local req_ctx_stolen = sm_service_ctx + 0x28 * 14
kw64(req_ctx_stolen, 0)
-- the bitmap0 flag can be left set
local bitmap0 = kr64(sm_service_bitmap0)
if bitfield_extract(bitmap0, 14, 1).lo == 0 then
    kw64(sm_service_bitmap0, bitmap0 + 0x4000)
end

function ccp_aes(buf_in_pa, buf_out_pa, buf_len, encrypt)
    local buf_pa = sbl_msg_buf_pa + 0x8000 + 0x800 * 14
    pw(buf_pa, string.rep(string.char(0), 0x800))

    local encrypt = encrypt or 0

    local key_pa = buf_pa + 0x100
    local iv_pa = buf_pa + 0x110
    local mail = make_svc_mail_hdr(kms_handle, 1) ..
        -- flags=0,mode=ecb,is_encrypt=encrypt,key_len=128
        string.char(0, 0, encrypt, 0) ..
        ub4(buf_len) ..
        ub8(0) ..
        ub8(buf_out_pa) ..
        ub8(buf_in_pa) ..
        ub8(key_pa) ..
        ub8(iv_pa)
    pw(buf_pa, mail)
    psp_send_msg(6, buf_pa)

    --tcp_file_write('aes_test.bin', pr(buf_pa, 0x800))
    if not psp_wait_result() then return false end
    local rv = pr32(buf_pa + 0x1c).lo
    if rv ~= 0 then log(string.format('ccp_aes error %8x', rv)) end
    return rv == 0
end

function ccp_xts(buf_in_pa, buf_out_pa, buf_len, encrypt)
    local buf_pa = sbl_msg_buf_pa + 0x8000 + 0x800 * 14
    pw(buf_pa, string.rep(string.char(0), 0x800))

    local encrypt = encrypt or 0
    local sector_size = 0x200

    local key_pa = buf_pa + 0x100
    -- a 0x10byte buffer. not written-back
    -- first 8bytes are filled as litte-endian sector index
    local sector_pa = buf_pa + 0x200
    local mail = make_svc_mail_hdr(kms_handle, 2) ..
        -- flags=key_id,sector_size=0x200,is_encrypt=encrypt,key_len=0x10
        string.char(0x08, 12, encrypt, 0) ..
        ub4(1) .. --num_sectors
        ub8(0) ..
        ub8(buf_out_pa) ..
        ub8(buf_in_pa) ..
        ub8(sector_pa) .. -- start_sector
        ub8(0x60)
    pw(buf_pa, mail)
    psp_send_msg(6, buf_pa)

    if not psp_wait_result() then return false end
    local rv = pr32(buf_pa + 0x1c).lo
    if rv ~= 0 then log(string.format('ccp_xts error %8x', rv)) end
    return rv == 0
end

function ccp_dma_copy(dst, src, len)
    local rv = ccp_aes(src, dst, len, 1)
    if not rv then return false end
    return ccp_aes(dst, dst, len, 0)
end

-- trying to send this again just results in psp bar2 [0x10564] = 0xf0000203,
-- which indicates the msg returned with error
function psp_connect()
    local buf_pa = sbl_msg_buf_pa
    pw(buf_pa, string.rep(string.char(0), 0x800))

    local msg = string.fromhex('0200000050005000') ..
        ub8(0) .. -- mid
        ub8(0) .. -- subcmd/pad
        -- connect msg body
        '0038' ..
        ub4(0) ..
        ub8(0xfee00000) .. -- msi_addr
        ub4(0x54) .. -- msi_data
        string.rep(string.char(0), 0x24) ..
        ub8(get_pa(kernel_text_base)) ..
        ub8(kernel_text_base) ..
        ub4(0xb70000) -- ktext_size
    pw(buf_pa, msg)
    psp_send_msg(2, buf_pa)

    tcp_file_write('psp_connect.bin', pr(buf_pa, 0x800))
    return psp_wait_result()
end

local index = 19
local addr = index * 0x10
--tmr_write32(addr + 8, 0)
--tmr_write32(addr + 0, base)
--tmr_write32(addr + 4, limit)
--tmr_write32(addr + 12, 0)
--tmr_write32(addr + 8, 0x3f07)
--log('tmr done')

function sceSblMp1DumpContext(dump_pa)
    local buf_pa = sbl_msg_buf_pa + 0x8000 + 0x800 * 15
    pw(buf_pa, string.rep(string.char(0), 0x800))

    local mail = make_sys_mail_hdr(0x28, 0x28, 2)..
        ub8(14) ..
        ub8(0) ..
        ub8(dump_pa) ..
        ub8(dump_pa + 0x40140) ..
        ub8(dump_pa + 0x40300)
    pw(buf_pa, mail)
    psp_send_msg_polled(5, buf_pa)

    if not psp_wait_result() then return false end
    local rv = pr32(buf_pa + 0x10).lo
    if rv ~= 0 then log(string.format('sceSblMp1DumpContext %8x', rv)) end
    return rv == 0
end

function sceSblServiceSpawn(name)
    local buf_pa = sbl_msg_buf_pa + 0x8000 + 0x800 * 14
    pw(buf_pa, string.rep(string.char(0), 0x800))

    local mail = make_sys_mail_hdr(0x28, 8, 1) ..
        ub8(0) ..
        ub4(0) .. ub4(0) .. ub4(0) .. ub4(0) .. -- args
        name
    pw(buf_pa, mail)
    psp_send_msg(5, buf_pa)

    if not psp_wait_result() then return nil end
    local rv = pr32(buf_pa + 0x10).lo
    if rv ~= 0 then
        log(string.format('sceSblServiceSpawn %8x', rv))
        return nil
    end
    return pr64(buf_pa + 0x18)
end

function sm_exit(handle)
    local buf_pa = sbl_msg_buf_pa + 0x8000 + 0x800 * 14
    pw(buf_pa, string.rep(string.char(0), 0x800))

    -- send mail to sm to tell it to exit
    local mail = make_svc_mail_hdr(handle, 0xffff)
    pw(buf_pa, mail)
    psp_send_msg(6, buf_pa)

    -- note: this wait is low-level...the psp may not have written the return value (buf+0x10) yet(?!)
    if not psp_wait_result() then return false end
    local rv = pr32(buf_pa + 0x10).lo
    if rv ~= 0 then log(string.format('sm_exit %8x', rv)) end
    return rv == 0

    -- send mail to sys to block until sm exits (sceSblServiceWaitForExit)
    -- not required, and handle seems to be unique.
    -- only helps if x86 wants to ensure it won't get blocked from loading next
    -- sm, while previous one is in process of unloading?
    --[[
    pw(buf_pa, string.rep(string.char(0), 0x800))

    local mail = make_sys_mail_hdr(0x10, 0, 1) ..
        ub8(1) ..
        ub8(handle)
    pw(buf_pa, mail)
    psp_send_msg(5, buf_pa)

    if not psp_wait_result() then return nil end
    local rv = pr32(buf_pa + 0x10).lo
    if rv ~= 0 then log(string.format('sceSblServiceWaitForExit %8x', rv)) end
    return rv == 0
    --]]
end

local kernel_text_base_pa = 0--get_pa(kernel_text_base)

if not aligned_buf then
    -- for some reason we can't free it, but let's not leak all over
    -- the place, either
    aligned_buf = call(sym.memalign, 0x1000, 0x1000)
end
--call(sym.memset, aligned_buf, 0x41, 0x1000)

local buf_pa = get_pa(aligned_buf)
--ccp_dma_copy(buf_pa, kernel_text_base_pa, 0x1000)
--ccp_xts(buf_pa, buf_pa, 0x1000, 0)

--tcp_file_write('tmr19_pre.bin', pr(Uint64:new(0x64000000), 0x800000))

--[[ uart
init
    reg2 &= ~0x1ff
    val = reg2
    reg2 = val | 0xC000
    val &= ~0x2600
    if arg1 == 2            ; called with arg1=1
        val |= 0x200
    if arg2 == 3            ; called with arg2=0
        val |= 0x400
    reg2 = val | 0x2000
    status = reg0
putc
    while reg3 & 0x800 != 0     ; txbusy
        pass
    reg1 = data
getc
    while reg3 & 0x10 == 0      ; rxready
        pass
    data = reg0
both x86 and mp4 are using titania uart1 (+0x100)
--]]
local uart_base = Uint64:new(0xC1010000 + 0x100)
pw32(uart_base + 4 * 3, 0x2000)
pw32(uart_base + 4 * 3, 0xe000)
tcp_file_write('uart_regs1.bin', pr(uart_base, 0x30))

--[[
local handle = sceSblServiceSpawn('80021002')
if handle then
    log('handle '..tostring(handle))
    sm_exit(handle)
end
--]]

--tcp_file_write('kernel_first_page.bin', pr(buf_pa, 0x1000))
--tcp_file_write('psp_bar.bin', kr4k(psp_bar2 + 0x10000))
--tcp_file_write('msg_buf.bin', pr(sbl_msg_buf_pa, 0x10000))
--tcp_file_write('tmr19.bin', pr(Uint64:new(0x64000000), 0x800000))

--local authmgr_buf0_pa = kr64(kernel_text_base + 0x3910318)
--local authmgr_buf1_pa = kr64(kernel_text_base + 0x3910318 + 8)
--tcp_file_write('authmgr_buf0.bin', pr(authmgr_buf0_pa, 0x4000))
--tcp_file_write('authmgr_buf1.bin', pr(authmgr_buf1_pa, 0x4000))

--[[
if not pupu_cr3 then
    pupu_cr3 = cr3_by_pid(0x43)
end
log(tostring(pupu_cr3))

local pupu_va_base = Uint64:new(0x16444000)
local pupu_va_len = 0x108000
local copybuf = malloc(pupu_va_len)
for i=0, pupu_va_len - 0x1000, 0x1000 do
    local va = pupu_va_base + i
    local pte_pa, pte = get_pte_ptr(va, pupu_cr3)
    local pa = get_pa(va, pupu_cr3)
    log(string.format('%8x ', i)..tostring(pte_pa)..' '..tostring(pte)..' '..tostring(pa))
    if bitfield_extract(pte, 58, 1).lo ~= 0 then
        pte = pte - Uint64:new(0, 0x4000000)
        pw64(pte_pa, pte)
    end
    if bitfield_extract(pte, 0, 1).lo ~= 0 then
        memcpy(copybuf + i, Uint64:new(pa.lo, pa.hi + 0x60), 0x1000)
        --tcp_file_write('pupu/dump_'..tostring(va), pr(pa, 0x1000))
    end
    collectgarbage()
end

tcp_file_write('pupu_'..tostring(pupu_va_base), r(copybuf, pupu_va_len))
free(copybuf)
--]]
