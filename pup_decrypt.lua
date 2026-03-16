function ioctl(fd, cmd, data)
    return call(sym.syscall, syscalls.ioctl, fd, cmd, data)
end

ub2 = function(x)
    local b0 = x % 256; x = (x - b0) / 256
    local b1 = x % 256
    return string.char(b0, b1)
end

function round_up_page(val)
    return lsl(bitfield_extract(val + 0x3fff, 14, 64 - 14), 14)
end

function malloc_mmap(len)
    local neg_1 = Uint64:new(0xffffffff, 0xffffffff)
    local len_aligned = round_up_page(len)
    local buf = call(sym.syscall, syscalls.mmap, 0, len_aligned, 3, 0x1000, neg_1, 0)
    if buf == neg_1 then error('mmap '..errno()) end
    call(sym.bzero, buf, len_aligned)
    return buf
end

function free_mmap(buf, len)
    local len_aligned = round_up_page(len)
    call(sym.syscall, syscalls.munmap, buf, len_aligned)
end

function tcp_file_read(path)
    local fd = tcp_host_open()
    if not fd then return false end

    local CMD_DOWNLOAD_FILE = 1
    local cmd = ub4(CMD_DOWNLOAD_FILE)..tcp_fmt_sized(path)
    local rv = write_all(fd, cmd, #cmd)
    local file_buf, file_len = nil, nil
    if rv then
        local scratch = malloc(4)
        rv = read_all(fd, scratch, 4)
        if rv then
            file_len = r32(scratch)
            file_buf = malloc_mmap(file_len)
            rv = read_all(fd, file_buf, file_len)
        end
    end
    close(fd)
    return rv, file_buf, file_len
end

function tcp_file_write_mem(path, buf, len)
    local fd = tcp_host_open()
    if not fd then return false end

    local len = force_Uint64(len).lo
    
    local CMD_UPLOAD_FILE = 0
    local cmd = ub4(CMD_UPLOAD_FILE)..tcp_fmt_sized(path)..ub4(len)
    local rv = write_all(fd, cmd, #cmd)
    if rv then rv = write_all(fd, buf, len) end
    close(fd)
    return rv
end

-- they are _IOWR('D', id, type)
local PUP_IOC_VERIFY_BLS_HDR = 0xC0104401
local PUP_IOC_DECRYPT_HDR = 0xC0184402
local PUP_IOC_VERIFY_WM = 0xC0184404
local PUP_IOC_DECRYPT_SEG = 0xC0184405
local PUP_IOC_DECRYPT_SEG_BLK = 0xC0284406

function pup_verify_bls_hdr(fd, buf, len)
    local args = ub8(buf)..ub8(len)
    local rv = ioctl(fd, PUP_IOC_VERIFY_BLS_HDR, args)
    return not rv:negative_s64()
end

function pup_decrypt_hdr(fd, buf, len, key_sel)
    local args = ub8(buf)..ub8(len)..ub8(key_sel)
    local rv = ioctl(fd, PUP_IOC_DECRYPT_HDR, args)
    return not rv:negative_s64()
end

function pup_verify_wm(fd, seg_idx, buf, len)
    local args = ub8(seg_idx)..ub8(buf)..ub8(len)
    local rv = ioctl(fd, PUP_IOC_VERIFY_WM, args)
    return not rv:negative_s64()
end

function pup_decrypt_seg(fd, seg_idx, buf, len)
    local args = ub8(seg_idx)..ub8(buf)..ub8(len)
    local rv = ioctl(fd, PUP_IOC_DECRYPT_SEG, args)
    return not rv:negative_s64()
end

function pup_decrypt_seg_block(fd, seg_idx, block_idx, block, block_len, info, info_len)
    local args = ub2(seg_idx)..ub2(block_idx)..ub4(0)..
        ub8(block)..ub8(block_len)..
        ub8(info)..ub8(info_len)
    local rv = ioctl(fd, PUP_IOC_DECRYPT_SEG_BLK, args)
    return not rv:negative_s64()
end

if not pupu_fd then
    pupu_fd = open('/dev/pup_update0', 0, 0)
end
if pupu_fd:negative_s64() then error('failed to open pup_update '..errno()) end

local rv, file_buf, file_len = tcp_file_read('pup_2.50/bls_hdr.bin')
if rv then
    local rv = pup_verify_bls_hdr(pupu_fd, file_buf, file_len)
    log('bls: '..tostring(rv))
    free_mmap(file_buf, file_len)
end

local rv, file_buf, file_len = tcp_file_read('pup_2.50/pup_hdr.bin')
if rv then
    local hdr1_len = r16(file_buf + 0xc)
    local hdr2_len = r16(file_buf + 0xe)
    local hdr_len = hdr1_len + hdr2_len
    local rv = pup_decrypt_hdr(pupu_fd, file_buf, hdr_len, 0)
    log('hdr: '..tostring(rv))
    tcp_file_write_mem('pup_2.50/pup_hdr.dec2.bin', file_buf, 0x4000)
    free_mmap(file_buf, file_len)
end

local seg_idx = 0
local rv, file_buf, file_len = tcp_file_read(string.format('pup_2.50/seg_%x.bin', seg_idx))
if rv then
    local rv = pup_verify_wm(pupu_fd, seg_idx, file_buf, file_len)
    log('wm: '..tostring(rv))
    free_mmap(file_buf, file_len)
end

--[[
local non_blocked_segs = { 1, 3, 5, 8, 0xa, 0xb, 0xc, 0xe, 0x10, 0x12, 0x13, 0x14, 0x16, 0x18}
for k, seg_idx in ipairs(non_blocked_segs) do
    collectgarbage()
    local rv, file_buf, file_len = tcp_file_read(string.format('pup_2.26/seg_%x.bin', seg_idx))
    if rv then
        local rv = pup_decrypt_seg(pupu_fd, seg_idx, file_buf, file_len)
        log(string.format('seg_%x: %s', seg_idx, tostring(rv)))
        if rv then
            tcp_file_write_mem(string.format('pup_2.26/seg_%x.dec.bin', seg_idx), file_buf, file_len)
        end
        free_mmap(file_buf, file_len)
    end
end
local non_blocked_segs = { 7, 9 }
for k, seg_idx in ipairs(non_blocked_segs) do
    collectgarbage()
    local rv, file_buf, file_len = tcp_file_read(string.format('pup_2.26/seg_%x.bin', seg_idx))
    if rv then
        local file_len_align_down = file_len - (file_len.lo % 0x10)
        local rv = pup_decrypt_seg(pupu_fd, seg_idx, file_buf, file_len_align_down)
        log(string.format('seg_%x: %s', seg_idx, tostring(rv)))
        if rv then
            tcp_file_write_mem(string.format('pup_2.26/seg_%x.dec.bin', seg_idx), file_buf, file_len)
        end
        free_mmap(file_buf, file_len)
    end
end
--]]

--[[
-- now get all the blocked segs
local blocked_seg_map = {
    [2] = 1, [4] = 3, [6] = 5, [0xd] = 0xc, [0xf] = 0xe, [0x11] = 0x10,
    [0x15] = 0x14, [0x17] = 0x16, [0x19] = 0x18
}
local blocked_seg_map = {
    [0x19] = 0x18
}
for seg_idx, info_idx in pairs(blocked_seg_map) do
    local info_rv, info_buf, info_len = tcp_file_read(string.format('pup_2.26/seg_%x.dec.bin', info_idx))
    local seg_rv, seg_buf, seg_len = tcp_file_read(string.format('pup_2.26/seg_%x.bin', seg_idx))
    log(string.format('info %s (%s:%s) seg %s (%s:%s)',
        tostring(info_rv), tostring(info_buf), tostring(info_len),
        tostring(seg_rv), tostring(seg_buf), tostring(seg_len)))
    -- this seems like a pain in the dick to do in lua
    local block_idx = 0
    local data_buf = seg_buf
    local data_len = 0x400
    local rv = pup_decrypt_seg_block(pupu_fd, seg_idx, block_idx, data_buf, data_len, info_buf, info_len)
    if rv then
        tcp_file_write_mem(
            string.format('pup_2.26/seg_%x.b%x.dec.bin', seg_idx, block_idx), data_buf, data_len)
    else log_err('pup_decrypt_seg_block')
    end

    free_mmap(info_buf, info_len)
    free_mmap(seg_buf, seg_len)
end
--]]

close(pupu_fd)
pupu_fd = nil

log('done')
