"""Tiny PowerPC encoder for the handful of instructions the co-op patches need (no external assembler)."""


def _d(op, rt, ra, imm): return (op << 26) | (rt << 21) | (ra << 16) | (imm & 0xffff)
def _x(rt, ra, rb, xo, rc=0): return (31 << 26) | (rt << 21) | (ra << 16) | (rb << 11) | (xo << 1) | rc


def mulli(rd, ra, imm): return _d(7, rd, ra, imm)
def addi(rd, ra, imm): return _d(14, rd, ra, imm)
def lwz(rd, off, ra): return _d(32, rd, ra, off)
def stw(rs, off, ra): return _d(36, rs, ra, off)
def add(rd, ra, rb): return _x(rd, ra, rb, 266)
def subf(rd, ra, rb): return _x(rd, ra, rb, 40)          # rd = rb - ra
def cmpw(ra, rb): return _x(0, ra, rb, 0)                # cr0
def mr(rd, rs): return _x(rs, rd, rs, 444)               # or rd, rs, rs
BGELR = 0x4c800020                                       # bclr 4,lt: return if !(cr0.lt)
BLR = 0x4e800020
BEQLR = 0x4d820020                                       # bclr 12,eq: return if cr0.eq
NOP = 0x60000000


def b(pc, target, link=False):
    disp = target - pc
    assert -0x2000000 <= disp < 0x2000000 and disp % 4 == 0, hex(disp)
    return (18 << 26) | (disp & 0x03fffffc) | (1 if link else 0)


def bl(pc, target): return b(pc, target, True)


def cmpwi(ra, imm): return _d(11, 0, ra, imm)
def li(rd, imm): return addi(rd, 0, imm)
def stwu(rs, off, ra): return _d(37, rs, ra, off)
def mflr(rd): return (31 << 26) | (rd << 21) | (0x100 << 11) | (339 << 1)
def mtlr(rs): return (31 << 26) | (rs << 21) | (0x100 << 11) | (467 << 1)
def mtctr(rs): return (31 << 26) | (rs << 21) | (0x120 << 11) | (467 << 1)
BCTRL = 0x4e800421


def bc(pc, target, bo, bi):
    disp = target - pc
    assert -0x8000 <= disp < 0x8000 and disp % 4 == 0, hex(disp)
    return (16 << 26) | (bo << 21) | (bi << 16) | (disp & 0xfffc)


def beq(pc, target): return bc(pc, target, 12, 2)
def bne(pc, target): return bc(pc, target, 4, 2)
def bge(pc, target): return bc(pc, target, 4, 0)


def lis(rd, imm): return _d(15, rd, 0, imm)
def ori(ra, rs, imm): return (24 << 26) | (rs << 21) | (ra << 16) | (imm & 0xffff)


def load32(rd, value):
    """lis/ori pair that loads an exact 32-bit constant."""
    return [lis(rd, value >> 16), ori(rd, rd, value & 0xffff)]


def slwi(ra, rs, n): return (21 << 26) | (rs << 21) | (ra << 16) | (n << 11) | ((31 - n) << 1)
def blt(pc, target): return bc(pc, target, 12, 0)


def lfs(fd, off, ra): return _d(48, fd, ra, off)
def stfs(fs, off, ra): return _d(52, fs, ra, off)
def fadds(fd, fa, fb): return (59 << 26) | (fd << 21) | (fa << 16) | (fb << 11) | (21 << 1)
def fmadds(fd, fa, fc, fb): return (59 << 26) | (fd << 21) | (fa << 16) | (fb << 11) | (fc << 6) | (29 << 1)
def fsubs(fd, fa, fb): return (59 << 26) | (fd << 21) | (fa << 16) | (fb << 11) | (20 << 1)
def fmuls(fd, fa, fc): return (59 << 26) | (fd << 21) | (fa << 16) | (fc << 6) | (25 << 1)
def fmr(fd, fb): return (63 << 26) | (fd << 21) | (fb << 11) | (72 << 1)
def fcmpo(fa, fb): return (63 << 26) | (fa << 16) | (fb << 11) | (32 << 1)        # into cr0


def cmplw(ra, rb): return (31 << 26) | (ra << 16) | (rb << 11) | (32 << 1)


def lhz(rd, off, ra): return _d(40, rd, ra, off)
def lbz(rd, off, ra): return _d(34, rd, ra, off)
def stb(rs, off, ra): return _d(38, rs, ra, off)
def lwzu(rd, off, ra): return _d(33, rd, ra, off)
def sth(rs, off, ra): return _d(44, rs, ra, off)


def ble(pc, target): return bc(pc, target, 4, 1)                  # not greater than (cr0)
def divwu(rd, ra, rb): return _x(rd, ra, rb, 459)
def mullw(rd, ra, rb): return _x(rd, ra, rb, 235)
def andi_(ra, rs, imm): return (28 << 26) | (rs << 21) | (ra << 16) | (imm & 0xffff)   # andi. (sets cr0)
def rlwinm(ra, rs, sh, mb, me): return (21 << 26) | (rs << 21) | (ra << 16) | (sh << 11) | (mb << 6) | (me << 1)
def cmplwi(ra, imm): return _d(10, 0, ra, imm)
def bgt(pc, target): return bc(pc, target, 12, 1)
