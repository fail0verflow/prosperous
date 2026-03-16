#!/usr/bin/env python3
from pathlib import Path
import struct

for path in Path('services/xfer/pcie').glob('cfg_*.bin'):
    bdf_str = path.name.split('.')[0].split('_')[1]
    b, d, f = int(bdf_str[1:-6], 16), int(bdf_str[-5:-3], 16), int(bdf_str[-2:], 16)
    buf = open(path.absolute(), 'rb').read()
    vid, did = struct.unpack_from('<HH', buf, 0)
    dev_class = struct.unpack_from('3B', buf, 9)[::-1]
    cmd_reg = buf[4]
    io_en, mem_en, bm_en = cmd_reg & 1 != 0 , cmd_reg & 2 != 0 , cmd_reg & 4 != 0 
    dev_type = buf[0xe]
    print(f'{bdf_str} {vid:04x}:{did:04x} class {dev_class} type {dev_type:02x}')
    l = []
    if io_en: l.append('io')
    if mem_en: l.append('mem')
    if bm_en: l.append('bme')
    if len(l): print('\t' + ','.join(l))
    
    if dev_type & 0x7f:
        # bridge
        bars = struct.unpack_from('<2I', buf, 0x10)
        busses = struct.unpack_from('3B', buf, 0x18)
        mem_ranges = struct.unpack_from('<4I2Q', buf, 0x20)
        mem_base, mem_lim = mem_ranges[:2]
        l = []
        l.append(f'busses: primary: {busses[0]:02x} secondary: {busses[1]:02x} subordinate: {busses[2]:02x}')
        if bars[0]: l.append(f'bar0: {bars[0]:08x}')
        if bars[1]: l.append(f'bar1: {bars[1]:08x}')
        l.append(f'mem {mem_base:08x}:{mem_lim:08x}')
        print('\t' + '\n\t'.join(l))
    else:
        l = []
        bars = struct.unpack_from('<6I', buf, 0x10)
        for i, bar in enumerate(bars):
            is_io = bar & 1
            is_64 = ((bar >> 1) & 0b11) == 0b10
            prefetchable = not is_io and bar & 0b1000
            addr = bar & ~0b11 if is_io else bar & ~0b1111
            if bar:
                line = f'bar{i}: {addr:08x}'
                if is_io: line += ' io'
                if is_64: line += ' 64bit'
                if prefetchable: line += ' prefetchable'
                l.append(line)
        print('\t' + '\n\t'.join(l))
