-- a53io ioctl 0x80186111 : nvme_dram_read(offset, len, buf)

local buf_len = 0x4000000

--local buf = call(sym.syscall, syscalls.mmap, 0, buf_len, 3, 0x1000, Uint64:new(0xffffffff, 0xffffffff), 0)
--if buf == Uint64:new(0xffffffff, 0xffffffff) then error('mmap') end
--call(sym.bzero, buf, buf_len)
local buf = malloc(0x100)

function a53io_enable_ctrlr()
    local fd = open('/dev/a53io', 0, 0)
    if fd:negative_s64() then return false end
    local rv = call(sym.syscall, syscalls.ioctl, fd, 0x80046103, buf)
    log('enable_ctrlr '..tostring(rv)..' '..errno())
    close(fd)
    if rv:negative_s64() then return false end
    return true
end

function a53io_disable_ctrlr()
    local fd = open('/dev/a53io', 0, 0)
    if fd:negative_s64() then return false end
    -- takes 1 arg: u32 flags, where bit1 means it should ignore active pkg_meta and force-disable
    memcpy(buf, ub4(0), 4)
    local rv = call(sym.syscall, syscalls.ioctl, fd, 0x80046104, buf)
    log('disable_ctrlr '..tostring(rv)..' '..errno())
    close(fd)
    if rv:negative_s64() then return false end
    return true
end

function a53io_dram_read(buf, offset, len)
    local fd = open('/dev/a53io', 0, 0)
    if fd:negative_s64() then return false end
    local cmd_buf = ub8(offset)..ub8(len)..ub8(buf)
    local rv = call(sym.syscall, syscalls.ioctl, fd, 0x80186111, cmd_buf)
    if rv:negative_s64() then
        log_err('nvme_dram_read '..tostring(rv))
    end
    close(fd)
    return rv:is_zero()
end

function make_pupu_cmd(index, buf, len)
    return ub8(index)..ub8(buf)..ub8(len)
end

function pup_read_fw_group(index)
    local fw_lens = { 0x4000000, 0x3E00000, 0x237800 }
    local fw_len = fw_lens[1 + index]
    local fd = open('/dev/pup_update0', 0, 0)
    if not fd:negative_s64() then
        local rv = call(sym.syscall, syscalls.ioctl, fd, 0xC018440A, make_pupu_cmd(index, buf, buf_len))
        if not rv:negative_s64() then
            tcp_file_write(string.format('fw_group_%x.bin', index), r(buf, fw_len))
        else
            log_err('ioctl')
        end
        close(fd)
    else log_err('open')
    end
end

function tcp_file_write_mem(path, buf, len)
    local fd = tcp_host_open()
    if not fd then return false end
    
    local CMD_UPLOAD_FILE = 0
    local cmd = ub4(CMD_UPLOAD_FILE)..tcp_fmt_sized(path)..ub4(len)
    local rv = write_all(fd, cmd, #cmd)
    if rv then rv = write_all(fd, buf, len) end
    close(fd)
    return rv
end

-- need to wait a bit after this returns
a53io_disable_ctrlr()

--for i=0,2,1 do pup_read_fw_group(i) end

--[[
if aligned_buf then
    pup_read_fw_group(0)
    memcpy(aligned_buf, buf + 0x78800, 0x1000)
end
--]]

--[[
local offset = Uint64:new(0)
for i=0,7,1 do
    if a53io_dram_read(buf, offset, buf_len) then
        tcp_file_write_mem(string.format('fcram/a53_dump_%s.bin', tostring(offset)), buf, buf_len)
    end
    offset = offset + buf_len
    collectgarbage()
end
--]]
--[[
local offset = Uint64:new(0)
for i=0,7,1 do
    memcpy(buf, Uint64:new(0xa0000000 + buf_len * i, 0x60), buf_len)
    tcp_file_write_mem(string.format('fcram/dump_%s.bin', tostring(offset)), buf, buf_len)
    offset = offset + buf_len
    collectgarbage()
end
--]]

log('done')
--call(sym.syscall, syscalls.munmap, buf, buf_len)
free(buf)