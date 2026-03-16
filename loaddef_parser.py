#!/usr/bin/env python3
from pathlib import Path
import sys, struct

load_defs_path = Path(sys.argv[1])

MAGICS = {
    0xAF390B1F: 'Oberon',
    0x3AB82DC4: 'Oberon Plus',
    0xc2758f76: 'Oberon Plus VMGuard',
    0xD94BF41F: 'Viola',
    0x17CAB2FC: 'Viola Disable DDR5',
    0xFC096B2F: 'Viola VMGuard',
    0xBB08E0EE: 'Viola VMGuard Disable DDR5',
}

def all_zero(buf): return all(map(lambda x: x == 0, buf))

def parse_name(buf):
    end = buf.find(0)
    if end < 0:
        end = None
    return str(buf[:end], 'ascii')

def bitmask2list(bits, vals: list):
    rv = []
    while bits:
        val = vals.pop(0)
        if bits & 1:
            rv.append(val)
        bits >>= 1
    return ','.join(rv)

class FwInfo:
    def __init__(self, buf):
        self.container = parse_name(buf[:8])
        self.filename = parse_name(buf[8:0x10])
        self.addr, self.size, self.flags, self.field_24 = struct.unpack_from('<2Q2I', buf, 0x10)
        assert self.field_24 == 0
        # flags:
        # bin_load = flags & 1. [SELF, BIN]
        # os_loadable = (flags >> 16) & 7. [GameOS, DiagOS, NyxOS]
        # bootmode_loadable = (flags >> 20) & 7. [S3, S4, S5]
        known_flags = (0b111 << 20) | (0b111 << 16) | 1
        unknown_flags = self.flags & ~known_flags
        assert unknown_flags == 0, f'unknown flags {unknown_flags:8x}'

    def flags2str(self):
        load_type = ('SELF', 'BIN')[self.flags & 1]
        os_loadable = bitmask2list((self.flags >> 16) & 7, ['GameOS', 'DiagOS', 'NyxOS'])
        bootmode_loadable = bitmask2list((self.flags >> 20) & 7, ['S3', 'S4', 'S5'])
        return f'type:{load_type:4} os:{os_loadable} boot:{bootmode_loadable}'

    def __repr__(self) -> str:
        return f'{self.container:8}:{self.filename:8} {self.addr:16x}:{self.size:16x} {self.flags2str()}'

class LoadDef:
    def __init__(self, path: Path) -> None:
        load_def_bin = path.read_bytes()
        self.magic, self.ver_major, self.ver_minor = struct.unpack_from('<I2H', load_def_bin, 0)
        if self.ver_major != 5: return
        self.fw_infos = []
        for pos in range(0x10, 0xb78, 0x28):
            self.fw_infos.append(FwInfo(load_def_bin[pos:pos+0x28]))

    def __repr__(self) -> str:
        name = MAGICS.get(self.magic, f'unknown_{self.magic:08x}')
        rv = [f'{name} v{self.ver_major}.{self.ver_minor}']
        for i, fw in enumerate(self.fw_infos):
            rv.append(f'{i:2d} {fw}')
        return '\n'.join(rv)

for path in load_defs_path.glob('load_defs_*.bin'):
    load_def = LoadDef(path)
    print(load_def)