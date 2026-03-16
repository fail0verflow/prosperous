
kproc = kr64(kthread + 8)
kvmspace = kr64(kproc + 0x200)
kpml4_kva = kr64(kvmspace + 0x300)
kpml4_pa = kr64(kvmspace + 0x308)

dmap = kpml4_kva - kpml4_pa

local pcie_cfg_base = dmap + Uint64:new(0xF0000000)

function pci_addr(b, d, f)
    return b * 0x100000 + d * 0x8000 + f * 0x1000
end

--[[]]
local ff_bytes = string.rep(string.char(0xff), 0x10)
local bus = 0x40
for d=0, 32-1, 1 do
    for f=0, 8-1, 1 do
        log(string.format('%02x:%02x:%02x', bus, d, f))
        local dump_addr = pcie_cfg_base + pci_addr(bus, d, f)
        local buf = kr4k(dump_addr)
        if ff_bytes ~= buf:sub(1, 0x10) then
            tcp_file_write(string.format('pcie/cfg_B%XD%02XF%02X.bin', bus, d, f), buf)
        end
    end
end
--]]

--[[
-- B0D01F01 maps 0x9ff18001:0xc4308000
local devmem = dmap + 0xe0600000 + 0x30000
-- x86 bldr describes mmio range 80000000:c4210000
-- c0100000: nvme vid/did: 104d/90eb
--   bar0 c4200000
--   bar2 c4300000
--   bar4 c4000000
--   subsystem 104d/9103
for i=0, 0x1000000-0x1000, 0x1000 do
    local addr = devmem + i
    tcp_file_write(string.format('pcie/mmio_%s.bin', tostring(addr - dmap)), kr4k(addr))
end
--]]

-- mp4 bars: 0xe0400000, 0xe06c0000
-- ccp bar2: 0xe0500000 bar5: 0xe06c6000
-- gpu bar0: 0xd0000000 bar2: 0xe0000000 bar4: 0x2000 (io) bar5: 0xe0600000
