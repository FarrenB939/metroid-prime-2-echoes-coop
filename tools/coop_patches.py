r"""Echoes co-op patches for Metroid Prime Trilogy NTSC-U (R3ME01, rs5mp2_p.dol
SHA-1 2375606f4e9429a699cfa02728b0bb1176421226). One source of truth for the live patcher and the Gecko codes.

Independent Gecko codes A-F (each can be enabled on its own; D, E, F are described at their definitions):

A. "keep inventory"
   1. (Removed 2026-10-24: spawn point RSET raise-only. RSET is vanilla again so the story's item loss works.)
   2. Multiplayer rules SpawnPlayer (FUN_8010cd94, death respawns) keeps the old powerups and skips its
      loadout loop entirely (3 words), so a respawn never hands out the respawn point's items.
   3. Arrivals (FUN_8023f45c, used by the session start and every elevator/portal world change) raise the
      player to the spawn point's loadout only when the MP rules say so (vt+0x20), and the MP rules always
      said yes. Now: only for the session's first spawn, i.e. while the player's Power Beam capacity is 0.

B. "campaign session"
   1. Match timer frozen: the rules tick (0x8010d528) adds dt to rules+0x8 with `stfs f0,0x8(r31)`
      at 0x8010d560; that store becomes a nop, so time-up never happens (HUD clock stays 10:00).
   2. Kill limit off: the deathmatch update's `blt` at 0x800764bc (kills < rules+0x3c) becomes `b`.
   3. Arena -> campaign: at CScriptWorldTeleporter::AcceptScriptMsg (0x8022da4c), a teleporter aimed at
      Sidehopper Station (MLVL a50a80cc / MREA 02690de1) is re-aimed at Temple Grounds / Landing Site
      (3bfa3eff / 62b0d67d), so picking that arena starts the campaign with every joined player.

C. "shared room transitions"
   A door (CScriptDock think FUN_801e6a84) switches the current area only when players[0] crosses its
   plane (`bl FUN_801e6cec(dock, mgr, players[0]+0x50)` at 0x801e6bf8). The replacement tests every
   player; when player k crosses, every other player is teleported near player k (FUN_80160cc4), 2.5 units
   further into the new room after a collision-ray check, and the area switch proceeds, so nobody is left
   in a room that unloads.

Hooks use the Gecko C2 (insert ASM) code type, so their code lives in Dolphin's managed code list.
Nothing is written to fixed low-memory addresses (0x80001800-0x80003000 belongs to the code handler
when cheats are on). Hook bodies are position-independent: game functions are called through ctr.

rs5mp2 is loaded by the Trilogy front end at runtime, so everything is gated on rs5mp2 being
resident (three words no patch here touches):
  0x8014bacc = 4082000c, 0x8023fe68 = 4bfff5f5, 0x804b4854 = 8010cd94

usage:
  coop_patches.py gecko A [B..]        print single features as their own codes (for reading)
  coop_patches.py gecko-all            print the combined Gecko code (gate, words, stubs)
  coop_patches.py onframe-all          print the [OnFrame] patch writing the hook bodies to MEM2
  coop_patches.py install-gecko        write all codes into the portable Dolphin's GameSettings\R3ME01.ini, enable cheats
  coop_patches.py live [--seconds N]   apply everything from Python (cheats OFF only: uses caves at 0x80002800+)
  coop_patches.py check                report every patch site in the running game
  coop_patches.py unpatch              restore every original word (cheats off first)
"""
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)                  # ppc; live/check/unpatch also need the unpublished dolmem.py
import ppc  # noqa: E402

GATE = {0x8014bacc: 0x4082000c, 0x8023fe68: 0x4bfff5f5, 0x804b4854: 0x8010cd94}

INIT_POWERUP, INCR_PICKUP = 0x8016d998, 0x8016db60
TELEPORTER_MSG = 0x8022da4c
ARENA = (0xa50a80cc, 0x02690de1)           # Sidehopper Station
CAMPAIGN = (0x3bfa3eff, 0x62b0d67d)        # Temple Grounds / Landing Site
DOCK_CROSSED = 0x801e6cec                  # bool(CScriptDock*, CStateManager&, const vec3* pos)
PLAYER_TELEPORT = 0x80160cc4               # (CPlayer*, const CTransform4f*, CStateManager&, bool)


class Asm:
    """Position-independent assembler: labels and relative branches; offsets from the hook start."""
    def __init__(self):
        self.w, self.labels, self.fix = [], {}, []

    def __call__(self, *words):
        self.w += list(words)

    def label(self, name):
        self.labels[name] = 4 * len(self.w)

    def br(self, kind, name):
        self.fix.append((len(self.w), kind, name)); self.w.append(0)

    def call(self, func):
        self(*ppc.load32(12, func), ppc.mtctr(12), ppc.BCTRL)

    def done(self):
        for i, kind, name in self.fix:
            self.w[i] = kind(4 * i, self.labels[name]) if callable(kind) else getattr(ppc, kind)(4 * i, self.labels[name])
        return self.w


def raise_only(field, setter):
    """Replaces `bl ReInitializePowerUp/ResetPickup(r3=state, r4=id, r5=loadout)`:
    only call `setter(state, id, loadout - current)` when current (state+0x58+id*12+field) is lower."""
    a = Asm()
    a(ppc.mulli(6, 4, 12), ppc.add(6, 6, 3), ppc.lwz(7, 0x58 + field, 6), ppc.cmpw(7, 5))
    a.br('bge', 'skip')
    a(ppc.subf(5, 7, 5))
    a.call(setter)
    a.label('skip')
    return a.done()


def loadout_first_spawn_only():
    """MP rules vt+0x20 (0x8010d580, `li r3,1; blr`) answers FUN_8023f45c's "apply this spawn point's
    loadout to player r5?" (r3 = rules, r4 = mgr, r5 = player index, from player+0x1388). Replaces the
    `li r3,1`: 1 only while the player's state (mgr+0x1504[r5]) has no Power Beam (capacity at +0x5c),
    which is true only between a new session building empty player states and their first spawn.
    Each player arrives at a different spawn point, and spawn points carry different start items, so on a
    new game only player 1 takes its spawn point's loadout; players 2-4 get a copy of player 1's health,
    suit and items instead (player 1 spawns first) and answer 0."""
    a = Asm()
    a(ppc.slwi(12, 5, 2), ppc.add(12, 12, 4), ppc.lwz(10, 0x1504, 12), ppc.lwz(12, 0x58 + 4, 10),
      ppc.li(3, 0), ppc.cmpwi(12, 0))
    a.br('bne', 'out')
    a(ppc.li(3, 1), ppc.cmpwi(5, 0))
    a.br('beq', 'out')
    a(ppc.lwz(7, 0x1504, 4), ppc.lwz(0, 0x58 + 4, 7), ppc.cmpwi(0, 0))
    a.br('beq', 'out')                    # player 1 not set up yet: fall back to this spawn point's loadout
    for off, size in STATE_COPY:
        a(ppc.addi(9, 7, off - 4), ppc.addi(11, 10, off - 4), ppc.li(8, size // 4))
        a.label(f'c{off:x}')
        a(ppc.lwzu(0, 4, 9), ppc.stwu(0, 4, 11), ppc.addi(8, 8, -1), ppc.cmpwi(8, 0))
        a.br('bne', f'c{off:x}')
    a(ppc.li(3, 0))
    a.label('out')
    return a.done()


def retarget():
    """Entry of WorldTeleporter::AcceptScriptMsg (r3 = teleporter): re-aim the arena at the campaign,
    then run the displaced first instruction `stwu r1,-0x20(r1)`."""
    a = Asm()
    a(ppc.lwz(11, 0x20, 3), *ppc.load32(12, ARENA[0]), ppc.cmpw(11, 12))
    a.br('bne', 'out')
    a(ppc.lwz(11, 0x24, 3), *ppc.load32(12, ARENA[1]), ppc.cmpw(11, 12))
    a.br('bne', 'out')
    a(*ppc.load32(12, CAMPAIGN[0]), ppc.stw(12, 0x20, 3), *ppc.load32(12, CAMPAIGN[1]), ppc.stw(12, 0x24, 3))
    a.label('out')
    a(0x9421ffe0)
    return a.done()


GS_GLOBAL = 0x805cb314                     # CGameState* (r13-0x634c); +0 current world MLVL
OPTS_GLOBAL = 0x805cb220                   # options/system data (r13-0x6440); +0x2c = save file slot
MP_RULES_VT = 0x804b4838
OPERATOR_NEW = 0x80315990                  # (size, name, 0)
ALLOC_NAME = 0x804a32c1                    # the name string the game passes for these allocations
LOAD_TASK_CTOR = 0x801ad590                # (mem, 0): 0x5c-byte NAND save task
LOAD_TASK_SET = 0x801ad764                 # (task or 0, 1)
LOAD_SLOT = 0x801adfcc                     # (task, slot): reads the file and loads that slot's game state
GAME_STATE_LOAD = 0x802a9e88               # (app, stream): replaces the game state with one read from a save
SET_RULES = 0x800bc414                     # (CGameState*, rules): owned pointer at +0x144/+0x148
MP_CONFIG = (0x14c, 0x64)                  # game state: MP match settings ('DTHM', player count, per-player data)
DEBUG_MARKS = False                        # temporary: counters at 0x80003cf0 (harness RAM)
COOP_SLOT = 2                              # co-op uses the third save file, leaving files 1-2 to single player
STATE_COPY = [(0x10, 8), (0x50, 0x8 + 109 * 12)]   # CPlayerState: health; suit, powerup count + 109 x amount/capacity


def copy_words(a, src, dst, size, tag):
    """r9 = src - 4, r10 = dst - 4 must be set; copies size bytes with lwzu/stwu (uses r0, r8)."""
    a(ppc.li(8, size // 4))
    a.label(tag)
    a(ppc.lwzu(0, 4, 9), ppc.stwu(0, 4, 10), ppc.addi(8, 8, -1), ppc.cmpwi(8, 0))
    a.br('bne', tag)


KILLS_PER_LIFE = 5                         # lives per player = the MP menu's Kill Limit / this (10 -> 2); 0 = off
LIVES_ADDR = 0x937f0000                    # MEM2 next to the hook bodies (not saved; set again on every session
                                           # start): +0 s32 pool (-1 = lives off), +4 lives per player (0 = off)
KILLS_ITEM = 0x40                          # deathmatch kill count item: shown in the HUD's centre counters,
                                           # used here to show the remaining lives (no kills happen in co-op)
RESPAWN_SKIP, MATCH_END = 0x80076498, 0x800764c0   # in the deathmatch update FUN_800762e8 (r28 rules, r29 mgr)


def far_to(target):
    return [*ppc.load32(12, target), ppc.mtctr(12), 0x4e800420]


def emit_set_pool(a, value_reg, states_base, stride, count_reg, tag):
    """Store value_reg in LIVES_ADDR and show it as every player's kill count (amount and capacity).
    states_base/stride: player state pointers at (states_base + stride*k), k < count_reg. Uses r9-r11."""
    a(*ppc.load32(11, LIVES_ADDR), ppc.stw(value_reg, 0, 11), ppc.li(10, 0))
    a.label(f'{tag}_loop')
    a(ppc.cmpw(10, count_reg))
    a.br('bge', f'{tag}_done')
    a(ppc.mulli(9, 10, stride), ppc.add(9, 9, states_base), ppc.lwz(9, 0, 9),
      ppc.stw(value_reg, 0x58 + KILLS_ITEM * 12, 9), ppc.stw(value_reg, 0x58 + KILLS_ITEM * 12 + 4, 9),
      ppc.addi(10, 10, 1))
    a.br('b', f'{tag}_loop')
    a.label(f'{tag}_done')


def emit_fill_pool(a, count_reg, states_base, stride, tag):
    """Pool = lives per player (LIVES_ADDR+4) x count_reg, shown as in emit_set_pool; lives off: pool = -1.
    Uses r7, r9-r11."""
    a(*ppc.load32(11, LIVES_ADDR), ppc.lwz(7, 4, 11), ppc.cmpwi(7, 0))
    a.br('beq', f'{tag}_off')
    a(ppc.mullw(7, 7, count_reg))
    emit_set_pool(a, 7, states_base, stride, count_reg, tag)
    a.br('b', f'{tag}_end')
    a.label(f'{tag}_off')
    a(ppc.li(7, -1), ppc.stw(7, 0, 11))
    a.label(f'{tag}_end')


def lives_respawn_gate():
    """At 0x80076428 (`mr r4,r29` before the 'may respawn' check and SpawnPlayer for a dead player whose
    timer ran out; r28 = rules, r29 = mgr). Pool left: continue as usual. Pool empty: if any player is
    still alive (state+4 bit 0x80) skip the respawn, so the player stays down and is re-checked every
    frame (a save station refill revives them); if nobody is alive, end the match like the kill limit
    does (results, then back to the multiplayer menu; Sidehopper Station then continues the save)."""
    a = Asm()
    a(*ppc.load32(11, LIVES_ADDR), ppc.lwz(0, 0, 11), ppc.cmpwi(0, 0))
    a.br('bne', 'go')
    a(ppc.lwz(8, 0x14f0, 29), ppc.li(10, 0))
    a.label('loop')
    a(ppc.cmpw(10, 8))
    a.br('bge', 'all_down')
    a(ppc.slwi(9, 10, 2), ppc.add(9, 9, 29), ppc.lwz(9, 0x1504, 9), ppc.lbz(9, 4, 9),
      (28 << 26) | (9 << 21) | (9 << 16) | 0x80)                                # andi. r9,r9,0x80 (alive)
    a.br('bne', 'someone_up')
    a(ppc.addi(10, 10, 1))
    a.br('b', 'loop')
    a.label('someone_up')
    a(*far_to(RESPAWN_SKIP))
    a.label('all_down')                   # results screen: show 0 kills rather than the lives display
    a(ppc.li(7, 0), ppc.addi(6, 29, 0x1504))
    emit_set_pool(a, 7, 6, 4, 8, 'clear')
    a(*far_to(MATCH_END))
    a.label('go')
    a(ppc.mr(4, 29))
    return a.done()


def lives_spend():
    """At 0x80076454 (`stb r25,0x4(r23)` right after SpawnPlayer revived a player): one life spent (unless off)."""
    a = Asm()
    a(*ppc.load32(11, LIVES_ADDR), ppc.lwz(7, 0, 11), ppc.cmpwi(7, 0))
    a.br('ble', 'out')                                                          # 0, or -1 = lives off
    a(ppc.addi(7, 7, -1), ppc.lwz(8, 0x14f0, 29), ppc.addi(6, 29, 0x1504))
    emit_set_pool(a, 7, 6, 4, 8, 'show')
    a.label('out')
    a(0x9b370004)
    return a.done()


SAVED_MESSAGES = (0x1dffe3e7, 0x47816a80)  # "saved" STRG after Yes: save station, gunship (No: 0x50b34a43, 0x0acdc324)


def lives_refill_on_save():
    """At the entry of the show-message function FUN_8024ac68 (r3 = mgr, r4 = STRG id; `stwu r1,-0x30(r1)`).
    Answering the save prompt (pause state 5) goes to state 0 and then shows a message: 'saved' (SAVED_MESSAGES)
    after Yes, another one after No, so refill the pool only for the 'saved' one. Players who are down get
    revived by the respawn check on the next frame. Uses r0, r6-r11."""
    a = Asm()
    for n, sid in enumerate(SAVED_MESSAGES):
        a(*ppc.load32(11, sid), ppc.cmpw(4, 11))
        a.br('beq', 'saved')
    a.br('b', 'out')
    a.label('saved')
    a(ppc.lwz(8, 0x14f0, 3), ppc.addi(6, 3, 0x1504))
    emit_fill_pool(a, 8, 6, 4, 'fill')
    a.label('out')
    a(ppc.stwu(1, -0x30, 1))
    return a.done()


MATCH_START_END = 0x800ba7d0               # epilogue of the MP match start FUN_800ba388 (`addi r11,r1,0xe0`).
                                           # By then it has rebuilt the game state (current world = Temple
                                           # Grounds for the re-aimed arena), installed the MP rules and settings
                                           # and written each player's controller index (state +0x588) and
                                           # per-player entry (gs +0x74 + 8i)
MP_WORLD_SETUP, GS_REFRESH, GS_REFRESH_94 = 0x800ba230, 0x800bb364, 0x8017e00c   # what the match start ends with


def load_coop_save():
    """At MATCH_START_END, when the match goes to the campaign (current world Temple Grounds): load the co-op
    save file (COOP_SLOT) the way single-player Continue does (FUN_800eb088..0dc). An empty file makes the
    game build a new-game state instead. Loading replaces the game state, so first keep what the match start
    set up: the rules object (detached from +0x144/+0x148 so the old state's destructor leaves it alone), the
    MP settings (+0x14c..+0x1b0), the per-player entries (+0x74..+0x94) and each player state's controller
    index (+0x588); put them into the loaded state, copy player 1's health, suit and items to the other
    player states, and redo the match start's last steps on the new state.
    Frame: 0x10 settings (0x64), 0x74 per-player entries (0x20), 0x94 controller indices (4 x 4),
    0xb0 r28 .. 0xbc r31, LR at F+4."""
    F = 0xd0
    off, size = MP_CONFIG
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.mflr(0), ppc.stw(0, F + 4, 1), ppc.stw(28, 0xb0, 1), ppc.stw(29, 0xb4, 1),
      ppc.stw(30, 0xb8, 1), ppc.stw(31, 0xbc, 1), *ppc.load32(11, GS_GLOBAL), ppc.lwz(31, 0, 11),
      ppc.lwz(0, 0, 31), *ppc.load32(12, CAMPAIGN[0]), ppc.cmpw(0, 12))
    a.br('bne', 'leave')
    a(ppc.lwz(28, 0x148, 31), ppc.li(0, 0), ppc.stb(0, 0x144, 31))              # detach the MP rules
    a(ppc.addi(9, 31, off - 4), ppc.addi(10, 1, 0x10 - 4), ppc.li(8, size // 4))
    a.br('bl', 'copy')
    a(ppc.addi(9, 31, 0x74 - 4), ppc.addi(10, 1, 0x74 - 4), ppc.li(8, 8))
    a.br('bl', 'copy')
    for k in range(4):
        a(ppc.lwz(6, 0x18 + 8 * k, 31), ppc.lwz(0, 0x588, 6), ppc.stw(0, 0x94 + 4 * k, 1))
    a(*ppc.load32(11, OPTS_GLOBAL), ppc.lwz(11, 0, 11), ppc.li(0, COOP_SLOT), ppc.stw(0, 0x2c, 11))
    a(ppc.li(3, 0x5c), *ppc.load32(4, ALLOC_NAME), ppc.li(5, 0))
    a.call(OPERATOR_NEW)
    a(ppc.mr(29, 3), ppc.cmpwi(3, 0))
    a.br('beq', 'noctor')
    a(ppc.li(4, 0))
    a.call(LOAD_TASK_CTOR)
    a(ppc.mr(29, 3))
    a.label('noctor')
    a(ppc.li(3, 0), ppc.li(4, 1))
    a.call(LOAD_TASK_SET)
    a(ppc.mr(3, 29), ppc.li(4, COOP_SLOT))
    a.call(LOAD_SLOT)
    a(ppc.mr(3, 29), ppc.li(4, 1))
    a.call(LOAD_TASK_SET)
    a(*ppc.load32(11, OPTS_GLOBAL), ppc.lwz(11, 0, 11), ppc.li(0, COOP_SLOT), ppc.stw(0, 0x2c, 11))   # the load resets it
    a(*ppc.load32(11, GS_GLOBAL), ppc.lwz(31, 0, 11))                            # the loaded game state
    if DEBUG_MARKS:
        a(*ppc.load32(12, 0x80003cf0), ppc.stw(31, 8, 12), ppc.lwz(0, 0, 31), ppc.stw(0, 0xc, 12))
    a(ppc.addi(9, 1, 0x10 - 4), ppc.addi(10, 31, off - 4), ppc.li(8, size // 4))
    a.br('bl', 'copy')
    a(ppc.addi(9, 1, 0x74 - 4), ppc.addi(10, 31, 0x74 - 4), ppc.li(8, 8))
    a.br('bl', 'copy')
    a(ppc.mr(3, 31), ppc.mr(4, 28))
    a.call(SET_RULES)
    for k in range(4):
        a(ppc.lwz(6, 0x18 + 8 * k, 31), ppc.lwz(0, 0x94 + 4 * k, 1), ppc.stw(0, 0x588, 6))
    a(ppc.lwz(7, 0x18, 31), ppc.addi(12, 31, 0x20), ppc.li(5, 3))              # player 1's state; entries 1..3
    a.label('each')
    for o, n in STATE_COPY:
        a(ppc.lwz(6, 0, 12), ppc.addi(9, 7, o - 4), ppc.addi(10, 6, o - 4), ppc.li(8, n // 4))
        a.br('bl', 'copy')
    a(ppc.addi(12, 12, 8), ppc.addi(5, 5, -1), ppc.cmpwi(5, 0))
    a.br('bne', 'each')
    # lives per player from the MP menu: rules +0x3c Kill Limit (steps of 5, 0 = none), +0x40 bit 0x40 = enabled
    a(ppc.li(7, 0), ppc.lbz(0, 0x40, 28), ppc.andi_(0, 0, 0x40))
    a.br('beq', 'per')
    a(ppc.lwz(7, 0x3c, 28), ppc.li(9, KILLS_PER_LIFE), ppc.divwu(7, 7, 9))
    a.label('per')
    a(*ppc.load32(11, LIVES_ADDR), ppc.stw(7, 4, 11))
    a(ppc.lwz(8, 0x38, 28), ppc.addi(6, 31, 0x18))                             # rules +0x38: players
    emit_fill_pool(a, 8, 6, 8, 'lives')                                        # game state player states, 8 apart
    a.call(MP_WORLD_SETUP)
    a(ppc.mr(3, 31))
    a.call(GS_REFRESH)
    a(ppc.addi(3, 31, 0x94))
    a.call(GS_REFRESH_94)
    a.label('leave')
    a(ppc.lwz(28, 0xb0, 1), ppc.lwz(29, 0xb4, 1), ppc.lwz(30, 0xb8, 1), ppc.lwz(31, 0xbc, 1),
      ppc.lwz(0, F + 4, 1), ppc.mtlr(0), ppc.addi(1, 1, F))
    a.br('b', 'out')
    a.label('copy')                       # r9 = src - 4, r10 = dst - 4, r8 = words (uses r0)
    a(ppc.lwzu(0, 4, 9), ppc.stwu(0, 4, 10), ppc.addi(8, 8, -1), ppc.cmpwi(8, 0))
    a.br('bne', 'copy')
    a(ppc.BLR)
    a.label('out')
    a(0x396100e0)
    return a.done()


REMOVE_CINEMA_CAMERA = 0x8005c024         # (camera manager, mgr): ends its current cinematic camera


def stop_camera_for_every_player():
    """Camera message handler FUN_801dafbc, 'stop' branch (0x801db1f8, `lwz r3,0x1514(r31)`; r30 = camera,
    r31 = mgr): a camera stopped by a non-player sender (a timer or relay) is only taken out of player 1's
    camera manager. Cameras started by a player (e.g. player 2 standing on a save station pad) go into that
    player's manager, so player 2 stayed stuck in an ended save-station camera, frozen and without control.
    Check every player's camera manager instead, then continue where the original branch does (0x801db25c)."""
    a = Asm()
    a(ppc.li(29, 0))
    a.label('loop')
    a(ppc.lwz(0, 0x14f0, 31), ppc.cmpw(29, 0))
    a.br('bge', 'done')
    a(ppc.slwi(3, 29, 2), ppc.add(3, 3, 31), ppc.lwz(3, 0x1514, 3), ppc.lwz(4, 0x2c, 3), ppc.lhz(0, 0x204, 4),
      ppc.lhz(5, 8, 30), ppc.cmplw(0, 5))
    a.br('bne', 'next')
    a(ppc.mr(4, 31))
    a.call(REMOVE_CINEMA_CAMERA)
    a.label('next')
    a(ppc.addi(29, 29, 1))
    a.br('b', 'loop')
    a.label('done')
    a(*ppc.load32(12, 0x801db25c), ppc.mtctr(12), 0x4e800420)                  # bctr: past the original branch
    return a.done()


PICKUP_TOUCH_AFTER_GRANT = 0x801f8d78      # CScriptPickup touch FUN_801f8b2c, right after the grant (`mulli r0,r25,12`)
SET_CAPACITY, SET_AMOUNT = 0x8016d984, 0x8016de44   # the pickup's "set" variants (pickup +0x1c8 bit 0x10)
ITEM_COUNTER = 0x2f                        # item the pickup also adds +0x15c of (counted per pickup)


def shared_pickup():
    """At PICKUP_TOUCH_AFTER_GRANT (r23 = pickup, r24 = mgr, r25 = item id, r30 = toucher's player index): the
    game has given the pickup to the touching player's state only. Give it the same way to every other
    player: ITEM_COUNTER += pickup +0x15c, then capacity += +0x158 and amount += +0x154 (or the set variants
    when +0x1c8 bit 0x10 is set), exactly as the touch handler does at 0x801f8d00..0x801f8d74.
    Frame: 0x8 r28, 0xc r29. Ends with the displaced `mulli r0,r25,12`."""
    F = 0x20
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.stw(28, 0x8, 1), ppc.stw(29, 0xc, 1), ppc.li(28, 0))
    a.label('loop')
    a(ppc.lwz(0, 0x14f0, 24), ppc.cmpw(28, 0))
    a.br('bge', 'done')
    a(ppc.cmpw(28, 30))
    a.br('beq', 'next')
    a(ppc.slwi(3, 28, 2), ppc.add(3, 3, 24), ppc.lwz(29, 0x1504, 3), ppc.cmpwi(29, 0))
    a.br('beq', 'next')
    for fn in (INIT_POWERUP, INCR_PICKUP):
        a(ppc.mr(3, 29), ppc.li(4, ITEM_COUNTER), ppc.lwz(5, 0x15c, 23))
        a.call(fn)
    a(ppc.lbz(0, 0x1c8, 23), 0x5400e7ff)                                        # rlwinm. r0,r0,28,31,31 (bit 0x10)
    a.br('bne', 'set')
    for fn, off in ((INIT_POWERUP, 0x158), (INCR_PICKUP, 0x154)):
        a(ppc.mr(3, 29), ppc.mr(4, 25), ppc.lwz(5, off, 23))
        a.call(fn)
    a.br('b', 'next')
    a.label('set')
    for fn, off in ((SET_CAPACITY, 0x158), (SET_AMOUNT, 0x154)):
        a(ppc.mr(3, 29), ppc.mr(4, 25), ppc.lwz(5, off, 23))
        a.call(fn)
    a.label('next')
    a(ppc.addi(28, 28, 1))
    a.br('b', 'loop')
    a.label('done')
    a(ppc.lwz(28, 0x8, 1), ppc.lwz(29, 0xc, 1), ppc.addi(1, 1, F), 0x1c19000c)   # displaced mulli r0,r25,12
    return a.done()


SET_SCAN_TIME = 0x8016e39c                 # (CPlayerState*, scan asset id, f1 fraction): +0x594/+0x59c sorted map
GET_SCAN_TIME = 0x8016e29c                 # (CPlayerState*, scan asset id) -> f1


def shared_scan_time():
    """Replaces `bl SET_SCAN_TIME(r3 = scanner's state, r4 = scan id, f1 = fraction)` at all three callers (the
    scan update 0x8014a474 and 0x8014a2d4, SetScanningState 0x80149e8c): store the same progress in every player's
    state, so a scan made by one player counts (logbook, scan colours, saved progress) for everyone.
    Frame: 0x8 r29 .. 0x10 r31, 0x14 fraction."""
    F = 0x20
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.stw(29, 0x8, 1), ppc.stw(30, 0xc, 1), ppc.stw(31, 0x10, 1), ppc.stfs(1, 0x14, 1),
      ppc.mr(31, 4), *ppc.load32(30, SM_ADDR), ppc.li(29, 0))
    a.label('loop')
    a(ppc.lwz(0, 0x14f0, 30), ppc.cmpw(29, 0))
    a.br('bge', 'done')
    a(ppc.slwi(3, 29, 2), ppc.add(3, 3, 30), ppc.lwz(3, 0x1504, 3), ppc.cmpwi(3, 0))
    a.br('beq', 'next')
    a(ppc.mr(4, 31), ppc.lfs(1, 0x14, 1))
    a.call(SET_SCAN_TIME)
    a.label('next')
    a(ppc.addi(29, 29, 1))
    a.br('b', 'loop')
    a.label('done')
    a(ppc.lwz(29, 0x8, 1), ppc.lwz(30, 0xc, 1), ppc.lwz(31, 0x10, 1), ppc.addi(1, 1, F))
    return a.done()


SF_GRANT_HANDLERS = (0x8020f780, 0x8020f838, 0x8020f8d4, 0x8020f9ac)   # special function types 31-34 (ACTN):
                                           # incr amount, incr capacity, incr both, set; prologue stwu r1,-0x20(r1)


def every_player_special_function(entry):
    """Entry of a power-up special function handler (r3 = special function, r4 = mgr, r5 = message). The
    handler gives the item to one player: FUN_802147ec(+0x170 selector, sender, mgr) = the sending player when
    +0x170 is -1, else player +0x170. Run the handler once per player with +0x170 set to that player, then
    restore it. Each run enters the handler after this hook (displaced stwu, then entry + 4).
    Frame: 0x8 r3, 0xc r4, 0x10 r5, 0x14 saved selector, 0x18 r31 (player), LR at F+4."""
    F = 0x30
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.mflr(0), ppc.stw(0, F + 4, 1), ppc.stw(3, 0x8, 1), ppc.stw(4, 0xc, 1),
      ppc.stw(5, 0x10, 1), ppc.stw(31, 0x18, 1), ppc.lwz(0, 0x170, 3), ppc.stw(0, 0x14, 1), ppc.li(31, 0))
    a.label('loop')
    a(ppc.lwz(4, 0xc, 1), ppc.lwz(0, 0x14f0, 4), ppc.cmpw(31, 0))
    a.br('bge', 'done')
    a(ppc.lwz(3, 0x8, 1), ppc.stw(31, 0x170, 3), ppc.lwz(5, 0x10, 1))
    a.br('bl', 'run')
    a(ppc.addi(31, 31, 1))
    a.br('b', 'loop')
    a.label('done')
    a(ppc.lwz(3, 0x8, 1), ppc.lwz(0, 0x14, 1), ppc.stw(0, 0x170, 3), ppc.lwz(31, 0x18, 1),
      ppc.lwz(0, F + 4, 1), ppc.mtlr(0), ppc.addi(1, 1, F), ppc.BLR)            # return to the handler's caller
    a.label('run')                        # the handler itself: displaced instruction, then entry + 4
    a(0x9421ffe0, *ppc.load32(12, entry + 4), ppc.mtctr(12), 0x4e800420)
    return a.done()


STATE_GRANT_SITE = 0x8020322c              # FUN_802031e4 (entity vt 0x804b8678) on ZERO: item +0x20, capacity +0x28,
                                           # amount +0x24 -> player 1's state only (r29 = object, r30 = mgr)


def every_player_state_grant():
    """Replaces `lwz r3,0x1504(r30)` at STATE_GRANT_SITE: do the object's InitPowerUp + IncrPickup for every
    player state, then continue after them (0x8020324c). Uses r29/r30 as the caller does; r31 saved."""
    F = 0x20
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.stw(31, 0x8, 1), ppc.li(31, 0))
    a.label('loop')
    a(ppc.lwz(0, 0x14f0, 30), ppc.cmpw(31, 0))
    a.br('bge', 'done')
    for fn, off in ((INIT_POWERUP, 0x28), (INCR_PICKUP, 0x24)):
        a(ppc.slwi(3, 31, 2), ppc.add(3, 3, 30), ppc.lwz(3, 0x1504, 3), ppc.lwz(4, 0x20, 29), ppc.lwz(5, off, 29))
        a.call(fn)
    a(ppc.addi(31, 31, 1))
    a.br('b', 'loop')
    a.label('done')
    a(ppc.lwz(31, 0x8, 1), ppc.addi(1, 1, F), *ppc.load32(12, 0x8020324c), ppc.mtctr(12), 0x4e800420)
    return a.done()


MAP_XF_MP = (40.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, -17.479, 0.0, 0.0, 40.0, 0.0)   # map placement in co-op (see below)
PLAYER_COUNT = 0x804e72e8 + 0x14f0         # sm player count (SM_ADDR is defined further down)


def load_player_count(a, r):
    a(*ppc.load32(r, PLAYER_COUNT), ppc.lwz(r, 0, r))


def map_only_when_open():
    """At 0x80157b84 (`cmpwi r5,0`: r5 = 1 draws the HUD's map block; r25 = HUD, r26 = mgr). The block draws
    the full map screen and, when the HUD's minimap flag is set, the corner minimap in normal play. With the
    multiplayer HUD frame the minimap would go through the map screen placement below (a huge wireframe over
    player 1's view), so with 2+ players draw the block only while the map screen is open (pause state 1)."""
    a = Asm()
    load_player_count(a, 11)
    a(ppc.cmpwi(11, 2))
    a.br('blt', 'keep')
    a(ppc.lwz(0, 0x2c0c, 26), ppc.cmpwi(0, 1))
    a.br('beq', 'keep')
    a(ppc.li(5, 0))
    a.label('keep')
    a(ppc.cmpwi(5, 0))
    return a.done()

PLAYER_CODE = (0x80140000, 0x80164000)    # CPlayer / player HUD code (callers that test their own camera manager)


def cinematic_check_shared():
    """Entry of FUN_8005c1d0(camera manager) = "cinematic camera active" (mgr+0x12 != invalid uid). The player
    code asks its own manager (player +0x12f0) to freeze input, hide the HUD, etc. Code D puts every cinematic
    camera into player 1's manager, so players 2-4 kept control during cutscenes: they could walk off the
    gunship while its save sequence ran, then that sequence's spawn point put them back on the ship, which
    counts as stepping on again: a new save prompt every time (a loop). With 2+ players, calls from the player
    code ask player 1's manager instead, so every player is held during a cutscene as Samus is in single
    player. Other callers (camera manager internals, drawing) are unchanged. LR = the caller's return address."""
    a = Asm()
    load_player_count(a, 11)
    a(ppc.cmpwi(11, 2))
    a.br('blt', 'done')
    a(ppc.mflr(11), ppc.lis(0, PLAYER_CODE[0] >> 16), ppc.cmplw(11, 0))
    a.br('blt', 'done')
    a(ppc.lis(0, PLAYER_CODE[1] >> 16), ppc.ori(0, 0, PLAYER_CODE[1] & 0xffff), ppc.cmplw(11, 0))
    a.br('bge', 'done')
    a(*ppc.load32(11, SM_ADDR + 0x1514), ppc.lwz(3, 0, 11))
    a.label('done')
    a(0xa0830012)                                                               # lhz r4,0x12(r3)
    return a.done()

SET_ZMODE = 0x803725d4                     # (enable, compare func, update) -> GXSetZMode, remembering the func
DRAW_MESSAGE_WINDOW = 0x800f8700           # (HUD +0x128 message window)


def message_on_top():
    """Replaces `bl DRAW_MESSAGE_WINDOW` at 0x80157d20 in the HUD draw FUN_801577fc (r3 = HUD+0x128). The text
    window (scan text, save messages) is drawn with the depth mode the map block leaves (test LEQUAL against the
    world, write): fine in single player, but in co-op another player's body standing in front of the camera is
    nearer than the window and covered it. With 2+ players draw it with the depth test off, then restore the
    mode the map block sets (1, LEQUAL, 1). Frame: 0x8 window, LR at F+4.
    NOT INSTALLED: tested 2026-10-23, the dark shape of player 2 still covered the window, so the overlap isn't
    the window's depth test (nor the player's vt+0x2c draw); kept for reference."""
    F = 0x10
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.mflr(0), ppc.stw(0, F + 4, 1), ppc.stw(3, 0x8, 1))
    load_player_count(a, 11)
    a(ppc.cmpwi(11, 2))
    a.br('blt', 'draw')
    a(ppc.li(3, 0), ppc.li(4, 7), ppc.li(5, 0))
    a.call(SET_ZMODE)
    a(ppc.lwz(3, 0x8, 1))
    a.call(DRAW_MESSAGE_WINDOW)
    a(ppc.li(3, 1), ppc.li(4, 3), ppc.li(5, 1))
    a.call(SET_ZMODE)
    a.br('b', 'done')
    a.label('draw')
    a(ppc.lwz(3, 0x8, 1))
    a.call(DRAW_MESSAGE_WINDOW)
    a.label('done')
    a(ppc.lwz(0, F + 4, 1), ppc.mtlr(0), ppc.addi(1, 1, F))
    return a.done()

HUD_ON_TOP = 0x937f0010                    # MEM2 flag: 1 while a paused HUD (map, menus, scan text) is being drawn


def hud_on_top_begin():
    """At the HUD draw entry FUN_801577fc (`stwu r1,-0x180(r1)`; r3 = HUD, r4 = mgr). While the game is paused
    (mgr+0x2c0c != 0: map, pause menu, save prompt, scan text) with 2+ players, set HUD_ON_TOP so every depth
    mode set during the HUD draw compares ALWAYS (see zmode_hud_on_top). Single player's paused screens draw over
    a captured image; co-op's draw over the live world, and near geometry (another player, a pillar) covered the
    text window and frame."""
    a = Asm()
    a(ppc.li(0, 0), ppc.lwz(11, 0x2c0c, 4), ppc.cmpwi(11, 0))
    a.br('beq', 'set')
    load_player_count(a, 11)
    a(ppc.cmpwi(11, 2))
    a.br('blt', 'set')
    a(ppc.li(0, 1))
    a.label('set')
    a(*ppc.load32(11, HUD_ON_TOP), ppc.stw(0, 0, 11), ppc.stwu(1, -0x180, 1))
    return a.done()


ZMODE_CACHE = 0x8050d272                   # byte: last depth mode set through FUN_8030817c (skips repeats)


def hud_on_top_end():
    """At the world draw entry FUN_80245504 (`stwu r1,-0x160(r1)`): clear HUD_ON_TOP (the HUD pass is over) and,
    if it was set, invalidate the depth-mode cache, so the world's next depth mode is really sent (the forced
    ALWAYS went to GX behind the cache's back)."""
    a = Asm()
    a(*ppc.load32(11, HUD_ON_TOP), ppc.lwz(0, 0, 11), ppc.cmpwi(0, 0))
    a.br('beq', 'out')
    a(ppc.li(0, 0), ppc.stw(0, 0, 11), *ppc.load32(11, ZMODE_CACHE), ppc.li(0, 0xff), ppc.stb(0, 0, 11))
    a.label('out')
    a(ppc.stwu(1, -0x160, 1))
    return a.done()


def zmode_hud_on_top():
    """At GXSetZMode 0x803ec8d0 (r3 enable, r4 compare func, r5 update; first instruction `lwz r9,-0x30f8(r2)`),
    which both the cached setter FUN_8030817c and the model material code call: while HUD_ON_TOP is set, compare
    ALWAYS (7)."""
    a = Asm()
    a(*ppc.load32(11, HUD_ON_TOP), ppc.lwz(11, 0, 11), ppc.cmpwi(11, 0))
    a.br('beq', 'keep')
    a(ppc.li(4, 7))
    a.label('keep')
    a(0x8122cf08)                                                               # lwz r9,-0x30f8(r2)
    return a.done()

CINEMATIC_ACTIVE = 0x8005c1d0              # (camera manager) -> 1 while a cinematic camera runs
FRONT_END_WORLD = 0xdaea74a3               # MLVL of the multiplayer menus


def emit_message_mode(a, yes, no):
    """Branch to `yes` when a message box is open (pause state 6) with 2+ players outside the multiplayer front end
    (world FRONT_END_WORLD: its menus run in the same state manager), else to `no`. Uses r11 and r12 only: at
    0x800e8654 r0 holds the caller's saved LR (`mfspr r0,LR` just before; an r0 version broke every return)."""
    a(*ppc.load32(11, SM_ADDR), ppc.lwz(12, 0x2c0c, 11), ppc.cmpwi(12, 6))
    a.br('bne', no)
    a(ppc.lwz(12, 0x14f0, 11), ppc.cmpwi(12, 2))
    a.br('blt', no)
    a(*ppc.load32(11, GS_GLOBAL), ppc.lwz(11, 0, 11), ppc.lwz(12, 0, 11), *ppc.load32(11, FRONT_END_WORLD),
      ppc.cmpw(12, 11))
    a.br('beq', no)
    a.br('b', yes)


def single_view_or_message():
    """Replaces the `bl` to the 'single full-screen view' test (code D: CINEMATIC_ACTIVE on player 1's camera manager)
    in the top-level draw (0x800e88a4) and the viewport layout (0x8024b584). Also true while a message box (scan
    text, save and script messages) is open with 2+ players, so it gets the whole screen over player 1's view, as in
    single player; message_hud_* keep the HUD pass running for player 1's HUD, which draws the box."""
    a = Asm()
    a.call(CINEMATIC_ACTIVE)
    a(ppc.cmpwi(3, 0))
    a.br('bne', 'out')
    emit_message_mode(a, 'msg', 'out')
    a.label('msg')
    a(ppc.li(3, 1))
    a.label('out')
    return a.done()


def message_hud_pass():
    """Replaces `cmpwi r4,0` at 0x800e8654 in the HUD pass FUN_800e864c (r4 = 'single view' flag, which skips the
    HUD loop: cinematics have no HUD). While a message box is open, run the loop anyway (it draws the box)."""
    a = Asm()
    emit_message_mode(a, 'msg', 'normal')
    a.label('msg')
    a(ppc.cmplw(4, 4))                                                          # eq: as if the flag were 0
    a.br('b', 'out')
    a.label('normal')
    a(ppc.cmpwi(4, 0))
    a.label('out')
    return a.done()


def message_hud_count():
    """Replaces `lwz r0,0x14f0(r3)` at 0x800e870c, the HUD loop bound (r3 = mgr): while a message box is open, draw
    player 1's HUD only (its viewport is the whole screen then)."""
    a = Asm()
    emit_message_mode(a, 'msg', 'normal')
    a.label('msg')
    a(ppc.li(0, 1))
    a.br('b', 'out')
    a.label('normal')
    a(ppc.lwz(0, 0x14f0, 3))
    a.label('out')
    return a.done()

def map_skip_backdrop():
    """Inline at 0x80157c14 (`bctrl` to (HUD frame +0x4e4)->+0x14 vt+0x24, CTR already loaded) in the HUD's map
    mode draw: that widget is single player's dimmed backdrop; the multiplayer HUD frame's version is a pale
    panel drawn over the map. With 2+ players skip the call."""
    a = Asm()
    load_player_count(a, 11)
    a(ppc.cmpwi(11, 2))
    a.br('bge', 'skip')
    a(ppc.BCTRL)
    a.label('skip')
    return a.done()


def map_depth_always():
    """Inline at 0x80157c84 (`li r4,6`: the HUD sets z-compare GEQUAL, no update, for the map). Single player's
    paused screen shows a captured image, so the map draws on a cleared depth buffer; in co-op the live world
    fills it and hides the map. With 2+ players use GX_ALWAYS (7)."""
    a = Asm()
    a(ppc.li(4, 6))
    load_player_count(a, 11)
    a(ppc.cmpwi(11, 2))
    a.br('blt', 'end')
    a(ppc.li(4, 7))
    a.label('end')
    return a.done()


def map_placement():
    """Replaces `bl MTX_CONCAT(r3 = out, r4 = scale, r5 = HUD+0x1e4)` at 0x80157cbc: the map's placement in the
    HUD is computed from anchor nodes of the HUD frame, and the multiplayer frame's anchors give a tiny map
    (scale 0.35 at depth -36). With 2+ players concatenate with MAP_XF_MP instead (single player's depth,
    scaled to the half-height co-op view; +/- zoom works on top)."""
    a = Asm()
    a.br('b', 'start')
    a.label('data')
    a(*[struct.unpack('>I', struct.pack('>f', v))[0] for v in MAP_XF_MP])
    a.label('start')
    load_player_count(a, 11)
    a(ppc.cmpwi(11, 2))
    a.br('blt', 'call')
    a.br('bl', 'here')
    a.label('here')
    a(ppc.mflr(5))
    a.fix.append((len(a.w), lambda pc, t: ppc.addi(5, 5, t - (pc - 4)), 'data')); a.w.append(0)
    a.label('call')
    a.call(0x80368234)
    return a.done()


PLANE_FROM_POINTS = 0x8033b77c            # (out vec4 {n.xyz, d}, a, b, c); n points to the crossed side
FOLLOW_STEP = 2.5                          # world units into the new room per follower
FOLLOW_LIFT = 1.0                          # followers are placed this far up and drop onto the floor
FOLLOW_MARGIN = 0.5                        # the clearance ray reaches this far past the follower's spot
RAY_CLEAR = 0x800a2ac8                     # (mgr, &start, &unit dir, &CMaterialFilter, f1 length) -> 1 if no static hit
MATERIAL_BIT = 0x802b8834                  # (r3:r4 = 64-bit value, r5 = n) -> r3:r4 << n
SOLID_BIT_SDA = -0x78d8                    # r13-relative: material bit the AI line-of-sight test treats as solid


def any_player_crossed():
    """Replaces `bl DOCK_CROSSED(r3=dock, r4=mgr, r5=players[0]+0x50)` inside the dock think, where the
    caller keeps r30 = dock and r31 = mgr. Result in r3 like the original call.

    Followers are teleported to the crossing player's transform moved FOLLOW_STEP * k along the door
    plane's normal (k = 1, 2, ...), i.e. further into the room being entered, so they neither land on top
    of the leader nor back on the old side of the door. The spot is checked first with the game's static
    collision ray (the one the AI line-of-sight test uses), cast from the leader's chest (FOLLOW_LIFT up)
    along the normal to FOLLOW_MARGIN past the spot. Clear: the follower is placed there FOLLOW_LIFT up and
    drops onto the floor, so a floor rising after the door can't swallow their feet. Blocked: the follower
    goes on the leader's own spot instead.
    Frame: 0x10 r27, 0x14 r28, 0x18 r29, 0x1c step, 0x20 plane, 0x30 transform (0x30), 0x60 filter (0x14),
    0x74 ray start, 0x80 accumulated offset, 0x84 lift, 0x88 margin."""
    F = 0x90
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.stw(27, 0x10, 1), ppc.stw(28, 0x14, 1), ppc.stw(29, 0x18, 1), ppc.li(29, 0))
    a.label('loop')
    a(ppc.slwi(6, 29, 2), ppc.add(6, 6, 31), ppc.lwz(5, 0x14f4, 6), ppc.cmpwi(5, 0))
    a.br('beq', 'next')
    a(ppc.addi(5, 5, 0x50), ppc.mr(3, 30), ppc.mr(4, 31))
    a.call(DOCK_CROSSED)
    a(ppc.cmpwi(3, 0))
    a.br('bne', 'found')
    a.label('next')
    a(ppc.addi(29, 29, 1), ppc.lwz(0, 0x14f0, 31), ppc.cmpw(29, 0))
    a.br('blt', 'loop')
    a(ppc.li(3, 0))
    a.br('b', 'out')
    a.label('found')
    a(ppc.slwi(6, 29, 2), ppc.add(6, 6, 31), ppc.lwz(28, 0x14f4, 6))                  # r28 = crossing player
    # plane of this dock in the current area (same lookup as FUN_801e6cec)
    a(ppc.lwz(6, 0x1dac, 31), ppc.lwz(6, 0x2c, 6), ppc.lwz(7, 0x1e44, 31), ppc.slwi(7, 7, 3), ppc.add(6, 6, 7),
      ppc.lwz(6, 4, 6), ppc.lwz(6, 0x94, 6), ppc.lwz(7, 0x2c8, 30), ppc.mulli(7, 7, 0x48), ppc.add(6, 6, 7))
    # only pull followers if the room on the other side is loaded (the caller's own condition, inlined from
    # FUN_8009af64/FUN_8009af7c: idx = entry->conn[entry->cur]; loaded == areas[idx]+0xd0 == 0x10)
    a(ppc.lwz(7, 4, 6), ppc.cmpwi(7, 0))
    a.br('beq', 'unloaded')
    a(ppc.lwz(7, 0, 6), ppc.slwi(7, 7, 3), ppc.lwz(8, 0xc, 6), ppc.add(8, 8, 7), ppc.lwz(7, 0, 8),
      ppc.lwz(8, 0x1dac, 31), ppc.lwz(9, 0x24, 8), ppc.cmplw(7, 9))
    a.br('bge', 'unloaded')
    a(ppc.lwz(8, 0x2c, 8), ppc.slwi(7, 7, 3), ppc.add(8, 8, 7), ppc.lwz(8, 4, 8), ppc.lwz(8, 0xd0, 8),
      ppc.cmpwi(8, 0x10))
    a.br('bne', 'unloaded')
    a(ppc.addi(3, 1, 0x20), ppc.addi(4, 6, 0x14), ppc.addi(5, 6, 0x20), ppc.addi(6, 6, 0x2c))
    a.call(PLANE_FROM_POINTS)
    fbits = lambda v: struct.unpack('>I', struct.pack('>f', v))[0]
    a(ppc.lis(0, fbits(FOLLOW_STEP) >> 16), ppc.stw(0, 0x1c, 1), ppc.li(0, 0), ppc.stw(0, 0x80, 1),
      ppc.lis(0, fbits(FOLLOW_LIFT) >> 16), ppc.stw(0, 0x84, 1), ppc.lis(0, fbits(FOLLOW_MARGIN) >> 16),
      ppc.stw(0, 0x88, 1))
    # filter {include = 1 << solid bit, exclude = 0, type 1}, built like the AI line-of-sight test does
    a(ppc.li(3, 0), ppc.li(4, 1), ppc.lwz(5, SOLID_BIT_SDA, 13))
    a.call(MATERIAL_BIT)
    a(ppc.stw(3, 0x60, 1), ppc.stw(4, 0x64, 1), ppc.li(0, 0), ppc.stw(0, 0x68, 1), ppc.stw(0, 0x6c, 1),
      ppc.li(0, 1), ppc.stw(0, 0x70, 1))
    for k in range(12):                                                                # copy leader transform
        a(ppc.lwz(0, 0x20 + 4 * k, 28), ppc.stw(0, 0x30 + 4 * k, 1))
    a(ppc.li(29, 0))
    a.label('tloop')
    a(ppc.slwi(6, 29, 2), ppc.add(6, 6, 31), ppc.lwz(27, 0x14f4, 6), ppc.cmpwi(27, 0))
    a.br('beq', 'tnext')
    a(ppc.cmpw(27, 28))
    a.br('beq', 'tnext')
    a(ppc.lfs(1, 0x80, 1), ppc.lfs(0, 0x1c, 1), ppc.fadds(1, 1, 0), ppc.stfs(1, 0x80, 1))   # f1 = k * step
    for j in range(3):                     # spot = leader + n*f1 (+ lift on z); ray start = leader (+ lift on z)
        a(ppc.lfs(2, 0x2c + 0x10 * j, 28))
        if j == 2:
            a(ppc.lfs(3, 0x84, 1), ppc.fadds(2, 2, 3))
        a(ppc.stfs(2, 0x74 + 4 * j, 1), ppc.lfs(3, 0x20 + 4 * j, 1), ppc.fmadds(2, 3, 1, 2),
          ppc.stfs(2, 0x3c + 0x10 * j, 1))
    a(ppc.lfs(0, 0x88, 1), ppc.fadds(1, 1, 0), ppc.mr(3, 31), ppc.addi(4, 1, 0x74), ppc.addi(5, 1, 0x20),
      ppc.addi(6, 1, 0x60))
    a.call(RAY_CLEAR)
    a(ppc.cmpwi(3, 0))
    a.br('bne', 'place')
    for j in range(3):                     # blocked: the leader's own spot
        a(ppc.lwz(0, 0x2c + 0x10 * j, 28), ppc.stw(0, 0x3c + 0x10 * j, 1))
    a.label('place')                       # last arg 1: also reset the morph ball camera (as SpawnPlayer does);
    a(ppc.mr(3, 27), ppc.addi(4, 1, 0x30), ppc.mr(5, 31), ppc.li(6, 1))   # with 0 it flew from the old spot
    a.call(PLAYER_TELEPORT)
    a.label('tnext')
    a(ppc.addi(29, 29, 1), ppc.lwz(0, 0x14f0, 31), ppc.cmpw(29, 0))
    a.br('blt', 'tloop')
    a.label('unloaded')
    a(ppc.li(3, 1))
    a.label('out')
    a(ppc.lwz(27, 0x10, 1), ppc.lwz(28, 0x14, 1), ppc.lwz(29, 0x18, 1), ppc.addi(1, 1, F))
    return a.done()


SM_ADDR = 0x804e72e8
SPAWN_NOTIFY = 0x8010ca50                  # rules->NotifyPlayers(mgr, idx, idx, 'SPWN', 0) at the end of SpawnPlayer
DISABLE_FILTER = 0x80056bf8                # CCameraFilterPass::DisableFilter(this, f1 = fade time)
FILTER_PASSES, FILTER_STRIDE, VIEWPORT_STRIDE = 0x1e98, 0x2c, 0x1e8
DEATH_FILTER_PASS = 1                      # the full-screen black fade left on after a death in the campaign
CLEAR_FADE_TIME = 0.5


def respawn_with_partner():
    """Replaces `bl SPAWN_NOTIFY` (0x8010d478) at the end of MP-rules SpawnPlayer (r27 = respawned player's
    index throughout the caller). Makes the original call, then:
    1. fades camera filter pass 1 back in on every viewport. Versus arenas do this with their own script
       objects; campaign rooms don't, so after a death both views stayed black.
    2. moves the respawned player onto the first other player (same position and facing).
       The rules pick the "best" spawn point in the whole world, which in the campaign is often in a room
       that isn't the current one, leaving the player in unrendered space.
       The partner's own spot is the only position known to be valid ground: an earlier version put the
       player 2.5 units behind the partner, which fell through the floor whenever a wall, step or slope
       was behind them. Players don't collide with each other, so sharing the spot is harmless.
    Frame: 0x8 fade time, 0x10 r28, 0x14 r29."""
    F = 0x20
    a = Asm()
    a.call(SPAWN_NOTIFY)
    fade = struct.unpack('>I', struct.pack('>f', CLEAR_FADE_TIME))[0]
    a(ppc.stwu(1, -F, 1), ppc.stw(28, 0x10, 1), ppc.stw(29, 0x14, 1),
      ppc.lis(0, fade >> 16), ppc.stw(0, 0x8, 1))
    for vp in range(4):
        a(*ppc.load32(11, SM_ADDR), ppc.lwz(0, 0x14f0, 11), ppc.cmpwi(0, vp + 1))
        a.br('blt', 'partner')
        a(ppc.addi(3, 11, FILTER_PASSES + DEATH_FILTER_PASS * FILTER_STRIDE + vp * VIEWPORT_STRIDE),
          ppc.lfs(1, 0x8, 1))
        a.call(DISABLE_FILTER)
    a.label('partner')
    a(*ppc.load32(28, SM_ADDR), ppc.li(29, 0))
    a.label('ploop')
    a(ppc.cmpw(29, 27))
    a.br('beq', 'pnext')
    a(ppc.slwi(6, 29, 2), ppc.add(6, 6, 28), ppc.lwz(6, 0x14f4, 6), ppc.cmpwi(6, 0))
    a.br('bne', 'found')
    a.label('pnext')
    a(ppc.addi(29, 29, 1), ppc.lwz(0, 0x14f0, 28), ppc.cmpw(29, 0))
    a.br('blt', 'ploop')
    a.br('b', 'done')
    a.label('found')                      # teleport to the partner's own transform (CPlayer +0x20)
    a(ppc.addi(4, 6, 0x20), ppc.slwi(6, 27, 2), ppc.add(6, 6, 28), ppc.lwz(3, 0x14f4, 6), ppc.mr(5, 28),
      ppc.li(6, 1))                       # 1: reset the morph ball camera too, like vanilla SpawnPlayer
    a.call(PLAYER_TELEPORT)
    a.label('done')
    a(ppc.lwz(28, 0x10, 1), ppc.lwz(29, 0x14, 1), ppc.addi(1, 1, F))
    return a.done()


def lives_unfade_partners():
    """At 0x80076414 (`lfs f0,0x0(r23)`, the per-frame branch for a player the rules have marked dead; r29 = mgr,
    r3 = that player, needed later). A death fades camera filter pass 1 to black on every viewport and only a
    respawn clears it, so while one player waits to respawn (or is held down with no lives left) the others
    play blind. Fade pass 1 back in on the viewports of players who are alive. The dead player's stays black
    during the respawn delay; with the pool empty it is lifted too, as that half then shows a partner's view
    (lives_spectate).
    Frame: 0x8 fade time, 0x10 r3, 0x14 r26 (loop index)."""
    F = 0x20
    fade = struct.unpack('>I', struct.pack('>f', CLEAR_FADE_TIME))[0]
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.stw(3, 0x10, 1), ppc.stw(26, 0x14, 1), ppc.lis(0, fade >> 16), ppc.stw(0, 0x8, 1),
      ppc.li(26, 0))
    a.label('loop')
    a(ppc.lwz(0, 0x14f0, 29), ppc.cmpw(26, 0))
    a.br('bge', 'done')
    a(ppc.slwi(9, 26, 2), ppc.add(9, 9, 29), ppc.lwz(9, 0x1504, 9), ppc.lbz(9, 4, 9),
      (28 << 26) | (9 << 21) | (9 << 16) | 0x80)                                # andi. r9,r9,0x80 (alive)
    a.br('bne', 'lift')
    a(*ppc.load32(11, LIVES_ADDR), ppc.lwz(0, 0, 11), ppc.cmpwi(0, 0))          # down: lift it only while
    a.br('bne', 'next')                                                         # spectating (pool empty)
    a.label('lift')
    a(ppc.mulli(3, 26, VIEWPORT_STRIDE), ppc.add(3, 3, 29),
      ppc.addi(3, 3, FILTER_PASSES + DEATH_FILTER_PASS * FILTER_STRIDE), ppc.lwz(0, 4, 3), ppc.cmpwi(0, 0))
    a.br('beq', 'next')                                                         # +4: target type, 0 = off
    a(ppc.lfs(1, 0x8, 1))
    a.call(DISABLE_FILTER)
    a.label('next')
    a(ppc.addi(26, 26, 1))
    a.br('b', 'loop')
    a.label('done')
    a(ppc.lwz(3, 0x10, 1), ppc.lwz(26, 0x14, 1), ppc.addi(1, 1, F), 0xc0170000)   # lfs f0,0x0(r23)
    return a.done()


def emit_spectate_target(a, mgr, vp):
    """While the pool is empty and player `vp` is down, set `vp` to the first player who is up. Uses r0, r8-r11."""
    a(*ppc.load32(11, LIVES_ADDR), ppc.lwz(0, 0, 11), ppc.cmpwi(0, 0))
    a.br('bne', 'out')
    a(ppc.slwi(9, vp, 2), ppc.add(9, 9, mgr), ppc.lwz(9, 0x1504, 9), ppc.lbz(9, 4, 9),
      (28 << 26) | (9 << 21) | (9 << 16) | 0x80)                                # andi. r9,r9,0x80 (alive)
    a.br('bne', 'out')
    a(ppc.li(10, 0), ppc.lwz(8, 0x14f0, mgr))
    a.label('loop')
    a(ppc.cmpw(10, 8))
    a.br('bge', 'out')
    a(ppc.slwi(9, 10, 2), ppc.add(9, 9, mgr), ppc.lwz(9, 0x1504, 9), ppc.lbz(9, 4, 9),
      (28 << 26) | (9 << 21) | (9 << 16) | 0x80)
    a.br('bne', 'found')
    a(ppc.addi(10, 10, 1))
    a.br('b', 'loop')
    a.label('found')
    a(ppc.mr(vp, 10))
    a.label('out')


def lives_spectate():
    """Out of lives, a downed player's half shows the view of a player who is up. Two parts:
    1. at 0x8024b844 (`rlwinm r0,r31,2,0,29`) in FUN_8024b72c(mgr, vp), which selects viewport vp for drawing:
       it stores players[vp], states[vp] and camera managers[vp] as the current player/state/camera manager
       (mgr+0x1da0/+0x1da4/+0x1da8); r30 = mgr, r31 = vp (restored from the stack on return). Select the
       partner instead, so the world is drawn from the partner's camera (the viewport index and screen area
       stay vp's).
    2. lives_spectate_hud: a dead player's HUD covers its viewport in black, so draw the partner's HUD there."""
    a = Asm()
    emit_spectate_target(a, 30, 31)
    a(0x57e0103a)                                                               # rlwinm r0,r31,2,0,29
    return a.done()


def lives_spectate_hud():
    """At 0x800dd9cc (`rlwinm r0,r31,3,0,28`) in FUN_800dd98c(game, mgr, vp), before it draws HUD
    (game+0x60+8*vp); r30 = mgr, r31 = vp (restored on return, unused after the draw)."""
    a = Asm()
    emit_spectate_target(a, 30, 31)
    a(0x57e01838)                                                               # rlwinm r0,r31,3,0,28
    return a.done()


MODIFY_DAMAGE = 0x802429ec                 # (CDamageInfo* out, mgr, uid* damager, uid* damagee, uid* radiusSender, info)
OBJECT_BY_ID = 0x8023e9fc                  # (mgr, const uid*) -> CEntity* or 0
CAST_WEAPON = 0x8029ede0                   # CEntity* -> CWeapon* or 0 (weapon owner uid at +0x2c8)


def no_friendly_fire():
    """Wraps MODIFY_DAMAGE (FUN_802429ec, the final CDamageInfo for every hit) at its entry, so one copy
    covers both callers. The hook saves the arguments in a frame of its own, points LR at its post-processing
    and then runs the displaced `stwu r1,-0x60(r1)`, so the function returns into the post code, which zeroes
    damage (+4), radius damage (+8) and knockback (+0x10) of the output when the damagee is a player and the
    damager or the radius sender is a player or a weapon owned by a player, then returns to the real caller.
    Args: r3 = out, r4 = mgr, r5 = &damager, r6 = &radiusSender, r7 = &damagee (ApplyDamage 0x80242338 takes
    (mgr, &damager, &damagee, &radiusSender, info, filter, knockback) and reorders them).
    Frame: 0x8 scratch uid, 0xc.. args r3-r7, 0x20.. saved r26-r31, caller LR at F+4."""
    F = 0x40
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.mflr(0), ppc.stw(0, F + 4, 1))
    a(*[ppc.stw(r, 0xc + 4 * (r - 3), 1) for r in range(3, 8)])
    a.br('bl', 'here')
    a.label('here')
    a(ppc.mflr(12))
    a.fix.append((len(a.w), lambda pc, t: ppc.addi(12, 12, t - (pc - 4)), 'post')); a.w.append(0)   # r12 = &post
    a(ppc.mtlr(12), 0x9421ffa0)                                         # displaced stwu r1,-0x60(r1)
    a.br('b', 'end')

    a.label('isp')                        # r0 = 1 if r3 (CEntity*, may be 0) is one of the players
    a(ppc.li(0, 0), ppc.cmpwi(3, 0), ppc.BEQLR, *ppc.load32(11, SM_ADDR + 0x14f0), ppc.li(10, 4))
    a.label('isp_loop')                   # players[0..3] at sm+0x14f4
    a(ppc.lwzu(12, 4, 11), ppc.cmpw(12, 3))
    a.br('beq', 'isp_yes')
    a(ppc.addi(10, 10, -1), ppc.cmpwi(10, 0))
    a.br('bne', 'isp_loop')
    a(ppc.BLR)
    a.label('isp_yes')
    a(ppc.li(0, 1), ppc.BLR)

    a.label('post')
    a(*[ppc.stw(r, 0x20 + 4 * (r - 26), 1) for r in range(26, 32)])
    a(ppc.lwz(31, 0xc, 1), ppc.lwz(30, 0x10, 1), ppc.lwz(29, 0x14, 1), ppc.lwz(27, 0x18, 1), ppc.lwz(28, 0x1c, 1))

    def player_check(uid_ptr_reg, yes):   # branch to `yes` if the entity *uid_ptr_reg is a player
        a(ppc.mr(3, 30), ppc.mr(4, uid_ptr_reg))
        a.call(OBJECT_BY_ID)
        a(ppc.mr(26, 3))
        a.br('bl', 'isp')
        a(ppc.cmpwi(0, 0))
        a.br('bne', yes)

    player_check(28, 'victim')
    a.br('b', 'done')
    a.label('victim')
    for n, src in enumerate((29, 27)):    # damager, radius sender
        player_check(src, 'zero')
        a(ppc.mr(3, 26), ppc.cmpwi(3, 0))
        a.br('beq', f'nw{n}')
        a.call(CAST_WEAPON)
        a(ppc.cmpwi(3, 0))
        a.br('beq', f'nw{n}')
        a(ppc.lhz(0, 0x2c8, 3), ppc.sth(0, 0x8, 1))
        a(ppc.mr(3, 30), ppc.addi(4, 1, 0x8))
        a.call(OBJECT_BY_ID)
        a.br('bl', 'isp')
        a(ppc.cmpwi(0, 0))
        a.br('bne', 'zero')
        a.label(f'nw{n}')
    a.br('b', 'done')
    a.label('zero')
    a(ppc.li(0, 0), ppc.stw(0, 0x4, 31), ppc.stw(0, 0x8, 31), ppc.stw(0, 0x10, 31))
    a.label('done')
    a(*[ppc.lwz(r, 0x20 + 4 * (r - 26), 1) for r in range(26, 32)])
    a(ppc.lwz(0, F + 4, 1), ppc.mtlr(0), ppc.addi(1, 1, F), ppc.BLR)
    a.label('end')
    return a.done()


IS_MULTIPLAYER = 0x8024b4fc                # (mgr) -> rules type not SNGL/FRND
SHOW_MESSAGE = 0x8024ac68                  # (mgr, STRG id, f1 time): paused message box (state 6)
CAST_ACTOR = 0x8029fd70                    # CEntity* -> CActor* or 0; CActor vt+0x78 = scan info (+4 = STRG id)


def scan_text_box():
    """Replaces `bl IS_MULTIPLAYER` at 0x80149ee8 in SetScanningState's 'scan complete' branch (r29 = mgr,
    r30 = player; the original then skips single-player's scan pane when multiplayer). Under MP rules, show
    the scanned object's scan text in the game's paused message box instead, and return 1 so the pane stays
    skipped. Single-player rules: returns 0, unchanged behaviour."""
    a = Asm()
    a(ppc.stwu(1, -0x20, 1), ppc.mr(3, 29))
    a.call(IS_MULTIPLAYER)
    a(ppc.cmpwi(3, 0))
    a.br('beq', 'out')
    a(ppc.lhz(0, 0x39c, 30), ppc.sth(0, 0x8, 1), ppc.mr(3, 29), ppc.addi(4, 1, 0x8))
    a.call(OBJECT_BY_ID)
    a.call(CAST_ACTOR)
    a(ppc.cmpwi(3, 0))
    a.br('beq', 'mp')
    a(ppc.lwz(12, 0, 3), ppc.lwz(12, 0x78, 12), ppc.mtctr(12), ppc.BCTRL, ppc.cmpwi(3, 0))
    a.br('beq', 'mp')
    a(ppc.lwz(4, 4, 3), ppc.cmpwi(4, -1))
    a.br('beq', 'mp')
    a(ppc.mr(3, 29), ppc.li(0, 0), ppc.stw(0, 0xc, 1), ppc.lfs(1, 0xc, 1))
    a.call(SHOW_MESSAGE)
    a.label('mp')
    a(ppc.li(3, 1))
    a.label('out')
    a(ppc.addi(1, 1, 0x20))
    return a.done()


PAUSE_STATES_ALLOWED = (0, 1, 3, 5, 6)      # close, map (button 1, code K), MP pause menu (button 2), save, message.


def message_state_gate():
    """Replaces `cmpwi r3,0` at 0x8024abb4 in SetPauseState(mgr, r31 = state), right after IsMultiplayer:
    the original ignores every request under MP rules. Let the states in PAUSE_STATES_ALLOWED through."""
    a = Asm()
    for state in PAUSE_STATES_ALLOWED:
        a(ppc.cmpwi(31, state))
        a.br('beq', 'allow')
    a(ppc.cmpwi(3, 0))
    a.br('b', 'end')
    a.label('allow')
    a(ppc.cmpw(3, 3))                      # cr0.eq = 1 -> the following bne is not taken
    a.label('end')
    return a.done()


def message_input_any_remote():
    """Replaces `cmpw r7,r0` at 0x800ddc28 in the HUD input dispatcher FUN_800ddc04(huds, r4 = mgr, r5 = input):
    each controller's input normally goes only to the HUD of the player using that controller (player state
    +0x588 == input +4), and the message box lives in player 1's HUD. While the message box (mgr+0x2c0c == 6)
    or the map (1, opened by any controller with code K) is open, send every controller's input to HUD 0 (first
    loop iteration) instead."""
    a = Asm()
    a(ppc.lwz(10, 0x2c0c, 4), ppc.cmpwi(10, 6))
    a.br('beq', 'any')
    a(ppc.cmpwi(10, 1))
    a.br('bne', 'normal')
    a.label('any')
    a(ppc.cmpwi(9, 0))                     # eq on the first iteration -> dispatch to HUD 0
    a.br('b', 'end')
    a.label('normal')
    a(ppc.cmpw(7, 0))
    a.label('end')
    return a.done()


def scan_in_multiplayer():
    """CPlayer can-scan check FUN_80149f3c: for non-player targets `if (IsMultiplayer(mgr)) return false`
    (0x8014a0e8 beq over the return). Always skip the return.
    Lock-on target update FUN_80166a38: in the Scan Visor single player picks the target with the scan target
    search FUN_8016a8fc (which includes scan-only points of interest, e.g. gate lock mechanisms), but under MP
    rules (`bne` at 0x80166a88 after IsMultiplayer) it falls back to the combat lock-on search, so only things
    that can be targeted in any visor could be scanned. Remove the branch.
    FUN_8016a8fc picks from a per-player buffer of object ids drawn on screen (player +0x138c), together with aim
    data that FUN_8016a410 updates each frame. The player update FUN_80148548 calls FUN_8016a410 only when the
    player is mgr+0x1da0, the player of the viewport being drawn: always Samus in single player, but in split
    screen that's set only while drawing (0 otherwise), so player 2's data never updated and the scan search
    found nothing for them. Call it for every player (0x80148578 `bne` over the call).
    scan_search_fallback() covers the rest."""
    return {0x8014a0e8: (0x4182000c, ppc.b(0x8014a0e8, 0x8014a0f4), 'Scan: allow scanning objects under MP rules'),
            0x80166a88: (0x40820030, ppc.NOP, 'Scan Visor: use the scan target search under MP rules'),
            0x80148578: (0x40820008, ppc.NOP, 'Scan Visor: update scan aim data for every player')}


CAST_TO_ACTOR = 0x8029fd70                # CEntity* -> CActor* or 0
SCAN_PICK_RANGE = 40.0                     # Scan Visor fallback picker: max distance from the eye
SCAN_PICK_COS2 = 0.96                      # and cos^2 of the max angle from the aim direction (about 11.5 degrees)


def scan_search_fallback():
    """Replaces `rlwinm r0,r3,16,16,31` at 0x80166aac, right after the Scan Visor's target search FUN_8016a8fc
    returns (r3 = uid << 16; r30 = player, r31 = mgr; next: sth r0,0x3c8(r30) = lock-on candidate).
    The search reads a per-player buffer of object ids that the GPU copies out of each viewport (graphics vt+0x138
    from FUN_8024bf80). In split screen only player 1's copy ever holds ids, so player 2 never got a target,
    and player 1 often doesn't either. With 2+ players, when it finds nothing, pick the target here instead:
    the active actor with scan info whose position is closest to the first-person camera's aim (camera manager
    +0x14, transform at +0x20), within SCAN_PICK_RANGE and the SCAN_PICK_COS2 cone; players excluded. Nothing
    there: continue at 0x80166ab8 (the combat lock-on search), as before this patch.
    Frame: 0x10 eye xyz, 0x1c aim xyz, 0x28 best dot^2, 0x2c best dist^2, 0x30 range^2, 0x40.. saved r25-r29."""
    F = 0x60
    bits = lambda v: struct.unpack('>I', struct.pack('>f', v))[0]
    a = Asm()
    a(ppc.rlwinm(0, 3, 16, 16, 31), ppc.cmplwi(0, 0xffff))
    a.br('bne', 'out')
    load_player_count(a, 11)
    a(ppc.cmpwi(11, 2))
    a.br('blt', 'out')
    a(ppc.stwu(1, -F, 1), ppc.mflr(0), ppc.stw(0, F + 4, 1),
      *[ppc.stw(r, 0x40 + 4 * (r - 25), 1) for r in range(25, 30)])
    a(ppc.lwz(3, 0x12f0, 30), ppc.lwz(3, 0x14, 3))                             # first-person camera
    for k, (eye, aim) in enumerate(((0x2c, 0x24), (0x3c, 0x34), (0x4c, 0x44))):
        a(ppc.lfs(0, eye, 3), ppc.stfs(0, 0x10 + 4 * k, 1), ppc.lfs(0, aim, 3), ppc.stfs(0, 0x1c + 4 * k, 1))
    for off, v in ((0x28, SCAN_PICK_COS2), (0x2c, 1.0), (0x30, SCAN_PICK_RANGE ** 2)):
        a(ppc.lis(0, bits(v) >> 16), ppc.ori(0, 0, bits(v) & 0xffff), ppc.stw(0, off, 1))
    a(ppc.li(27, -1), ppc.lwz(29, 0x810, 31), ppc.lhz(28, 0x2008, 29))         # best uid, list, first index
    a.label('loop')
    a(ppc.cmplwi(28, 0xffff))
    a.br('beq', 'done')
    a(ppc.slwi(9, 28, 3), ppc.add(9, 9, 29), ppc.lwz(26, 4, 9), ppc.lhz(28, 8, 9), ppc.cmpwi(26, 0))
    a.br('beq', 'loop')
    a(ppc.lwz(0, 0x1c, 26), ppc.cmpwi(0, 0))                                   # active (bit 31)
    a.br('bge', 'loop')
    a(ppc.li(10, 0))                                                           # not a player
    a.label('ploop')
    a(ppc.slwi(9, 10, 2), ppc.add(9, 9, 31), ppc.lwz(9, 0x14f4, 9), ppc.cmpw(9, 26))
    a.br('beq', 'loop')
    a(ppc.addi(10, 10, 1), ppc.lwz(0, 0x14f0, 31), ppc.cmpw(10, 0))
    a.br('blt', 'ploop')
    a(ppc.mr(3, 26))
    a.call(CAST_TO_ACTOR)
    a(ppc.cmpwi(3, 0))
    a.br('beq', 'loop')
    a(ppc.lwz(9, 0xbc, 3), ppc.cmpwi(9, 0))                                   # scan info (as actor vt+0x78)
    a.br('beq', 'loop')
    a(ppc.lwz(9, 8, 9), ppc.cmpwi(9, 0))
    a.br('beq', 'loop')
    # v = pos - eye (f1-f3), dist^2 (f4), dot with aim (f5)
    for k in range(3):
        a(ppc.lfs(1 + k, 0x50 + 4 * k, 26), ppc.lfs(0, 0x10 + 4 * k, 1), ppc.fsubs(1 + k, 1 + k, 0))
    a(ppc.fmuls(4, 1, 1), ppc.fmadds(4, 2, 2, 4), ppc.fmadds(4, 3, 3, 4))
    a(ppc.lfs(0, 0x30, 1), ppc.fcmpo(4, 0))
    a.br('bgt', 'loop')
    a(ppc.lfs(0, 0x1c, 1), ppc.fmuls(5, 1, 0), ppc.lfs(0, 0x20, 1), ppc.fmadds(5, 2, 0, 5),
      ppc.lfs(0, 0x24, 1), ppc.fmadds(5, 3, 0, 5))
    a(ppc.fsubs(0, 5, 5), ppc.fcmpo(5, 0))                                     # dot <= 0: behind
    a.br('ble', 'loop')
    a(ppc.fmuls(5, 5, 5))                                                      # dot^2
    a(ppc.lfs(0, 0x2c, 1), ppc.fmuls(6, 5, 0), ppc.lfs(0, 0x28, 1), ppc.fmuls(7, 0, 4), ppc.fcmpo(6, 7))
    a.br('ble', 'loop')                                                        # dot^2/d^2 <= best: no
    a(ppc.stfs(5, 0x28, 1), ppc.stfs(4, 0x2c, 1), ppc.lhz(27, 8, 26))
    a.br('b', 'loop')
    a.label('done')
    a(ppc.rlwinm(0, 27, 0, 16, 31),
      *[ppc.lwz(r, 0x40 + 4 * (r - 25), 1) for r in range(25, 30)],
      ppc.lwz(3, F + 4, 1), ppc.mtlr(3), ppc.addi(1, 1, F), ppc.cmplwi(0, 0xffff))
    a.br('bne', 'out')
    a(*far_to(0x80166ab8))
    a.label('out')
    return a.done()


ENTITY_THINK = 0x80240994                  # (mgr, CEntity*, f1 dt): calls the entity's vt+0x14 Think
CAST_ENTITY = 0x8029da94                   # (CEntity*, type id) -> object if it IsA that type, else 0
PATTERNED = 4                              # CPatterned: every AI enemy


# Enemies that store the player they fight as a uid, set once (single player has one player) and never changed:
# (type id, offset). Code F keeps it pointing at the nearest player while it holds a player's uid (a field
# holding anything else is left alone). Offsets: rso_targets.py (a players[0] uid stored into the object in the
# module); type ids and field checks: live (world_scan.py, check_targets.py), 2026-10-23.
#   117 Boost Guardian   +0x1098  set in its collision handler; stayed on P1 all fight (P2 alone: ~50 vs ~330 dmg)
#   149 Alpha Blogg      +0x9b0   set at setup; stayed 0x400 with P2 7 units away and P1 60 away
#   132 Space Pirate     +0x31c   took P1 (60 away) over P2 (30 away)
#   118 Jump Guardian    +0x9f0   one-line setter from players[0]; field reads 0xffff idle
#   113 Quadraxis        +0x1052  one-line setter (type 112's +0x1052 isn't a uid)
#   116 Ing              +0xd7c,  134/135 Splitter +0xcd8/+0xf0e,  127 Rezbit +0xca2: same pattern, uid fields
# Dark Samus (111, +0x700) updates its own field (followed P2 live), so it isn't listed.
STORED_TARGETS = [(117, 0x1098), (149, 0x9b0), (132, 0x31c), (118, 0x9f0), (113, 0x1052), (116, 0xd7c),
                  (134, 0xcd8), (135, 0xf0e), (127, 0xca2)]


def nearest_player_think(prethink=False):
    """Replaces `bl ENTITY_THINK(r3 = mgr, r4 = entity, f1 = dt)` at 0x80240be8 in the per-frame entity loop.
    With prethink=True it instead replaces the PreThink pass's `bctrl` at 0x80240d50 (FUN_80240c40: r3 =
    entity, r4 = mgr, f1 = dt, CTR = entity vt+0x10), which bosses such as the Boost Guardian use for their
    targeting too; the call is redone through the vtable since the far jump here uses CTR.
    Enemy code reads players[0] (sm+0x14f4) directly for its attack range checks (CPatterned InRange /
    InMinRange / InMaxRange predicates) and the 'player too far' leash timer (+0x3e0, counted against
    players[0] only), so an enemy fighting player 2 gave up after 5 s whenever player 1 was more than 25
    units away. For a CPatterned with 2+ players present, swap the nearest player and its CPlayerState
    (sm+0x1504) into slot 0 for the duration of its Think, then swap back. For the bosses in STORED_TARGETS,
    also point their stored target uid at that player.
    Frame: 0x8 dt, 0x10.. saved r28-r31; r29 = slot swapped with 0 (0 = none)."""
    F = 0x20
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.stw(28, 0x10, 1), ppc.stw(29, 0x14, 1), ppc.stw(30, 0x18, 1), ppc.stw(31, 0x1c, 1),
      ppc.stfs(1, 0x8, 1), *((ppc.mr(31, 4), ppc.mr(30, 3)) if prethink else (ppc.mr(31, 3), ppc.mr(30, 4))),
      ppc.li(29, 0), ppc.lwz(0, 0x14f0, 31), ppc.cmpwi(0, 2))
    a.br('blt', 'think')
    a(ppc.mr(3, 30), ppc.li(4, PATTERNED))
    a.call(CAST_ENTITY)
    a(ppc.cmpwi(3, 0))
    a.br('beq', 'think')
    a(ppc.li(28, 0))
    a.label('loop')                       # f5 = best squared distance, r29 = its slot
    a(ppc.slwi(5, 28, 2), ppc.add(5, 5, 31), ppc.lwz(5, 0x14f4, 5))
    for k in range(3):
        a(ppc.lfs(2, 0x50 + 4 * k, 5), ppc.lfs(3, 0x50 + 4 * k, 30), ppc.fsubs(2, 2, 3),
          ppc.fmuls(4, 2, 2) if k == 0 else ppc.fmadds(4, 2, 2, 4))
    a(ppc.cmpwi(28, 0))
    a.br('beq', 'take')
    a(ppc.fcmpo(4, 5))
    a.br('bge', 'next')
    a.label('take')
    a(ppc.fmr(5, 4), ppc.mr(29, 28))
    a.label('next')
    a(ppc.addi(28, 28, 1), ppc.lwz(0, 0x14f0, 31), ppc.cmpw(28, 0))
    a.br('blt', 'loop')
    if STORED_TARGETS and not prethink:   # bosses that remember a player: point it at r29 (main Think only)
        # own type id = immediate of the class's IsA function (vt+0xc: `cmpwi r4,N`), compared without calls
        a(ppc.lwz(3, 0, 30), ppc.lwz(3, 0xc, 3), ppc.lwz(4, 0, 3), ppc.rlwinm(5, 4, 16, 16, 31),
          ppc.cmplwi(5, 0x2c04))
        a.br('bne', 'st_done')
        a(ppc.rlwinm(4, 4, 0, 16, 31))
        for n, (type_id, off) in enumerate(STORED_TARGETS):
            a(ppc.cmplwi(4, type_id))
            a.br('bne', f'st{n}')
            a(ppc.lhz(6, off, 30), ppc.li(28, 0))
            a.label(f'st{n}_loop')
            a(ppc.lwz(0, 0x14f0, 31), ppc.cmpw(28, 0))
            a.br('bge', 'st_done')                            # not a player's uid: leave it
            a(ppc.slwi(7, 28, 2), ppc.add(7, 7, 31), ppc.lwz(7, 0x14f4, 7), ppc.lhz(7, 8, 7), ppc.addi(28, 28, 1),
              ppc.cmpw(6, 7))
            a.br('bne', f'st{n}_loop')
            a(ppc.slwi(7, 29, 2), ppc.add(7, 7, 31), ppc.lwz(7, 0x14f4, 7), ppc.lhz(7, 8, 7), ppc.sth(7, off, 30))
            a.br('b', 'st_done')
            a.label(f'st{n}')
        a.label('st_done')
    a.br('bl', 'swap')
    a.label('think')
    if prethink:
        a(ppc.mr(3, 30), ppc.mr(4, 31), ppc.lfs(1, 0x8, 1), ppc.lwz(12, 0, 30), ppc.lwz(12, 0x10, 12),
          ppc.mtctr(12), ppc.BCTRL)
    else:
        a(ppc.mr(3, 31), ppc.mr(4, 30), ppc.lfs(1, 0x8, 1))
        a.call(ENTITY_THINK)
    a.br('bl', 'swap')
    a(ppc.lwz(28, 0x10, 1), ppc.lwz(29, 0x14, 1), ppc.lwz(30, 0x18, 1), ppc.lwz(31, 0x1c, 1), ppc.addi(1, 1, F))
    a.br('b', 'end')
    a.label('swap')                       # exchange slot 0 and slot r29 of players and player states
    a(ppc.cmpwi(29, 0), ppc.BEQLR, ppc.slwi(5, 29, 2), ppc.add(5, 5, 31))
    for base in (0x14f4, 0x1504):
        a(ppc.lwz(6, base, 31), ppc.lwz(7, base, 5), ppc.stw(7, base, 31), ppc.stw(6, base, 5))
    a(ppc.BLR)
    a.label('end')
    return a.done()



def relevant_player_message():
    """Replaces the `bctrl` to AcceptScriptMsg (vt+0x18; r3 = entity, r4 = mgr, r5 = message: +2 sender uid,
    +4 target uid, +8 kind) in both message dispatchers: immediate FUN_8024b388 (0x8024b3d0) and the queue pump
    FUN_80244c08 (0x80244c70), which delivers everything sent with FUN_8024b3ec (damage, script connections).
    Enemy message handlers read players[0] too: the Boost Guardian's checks "was I hit by a weapon owned by
    players[0]" and measures its distance to players[0] there, so it ignored player 2's shots. Code F's swap
    only covers Think/PreThink. For a CPatterned with 2+ players, swap into slot 0 the sender if it's a player,
    else the owner if the sender is a player's weapon, else the nearest player; call; swap back.
    Frame: 0x8 scratch, 0x10.. saved r26-r31, LR at F+4. r28 entity, r30 mgr, r31 message, r29 slot."""
    F = 0x30
    a = Asm()
    a(ppc.stwu(1, -F, 1), ppc.mflr(0), ppc.stw(0, F + 4, 1), *[ppc.stw(r, 0x10 + 4 * (r - 26), 1) for r in range(26, 32)],
      ppc.mr(28, 3), ppc.mr(30, 4), ppc.mr(31, 5), ppc.li(29, 0), ppc.lwz(0, 0x14f0, 30), ppc.cmpwi(0, 2))
    a.br('blt', 'deliver')
    a(ppc.mr(3, 28), ppc.li(4, PATTERNED))
    a.call(CAST_ENTITY)
    a(ppc.cmpwi(3, 0))
    a.br('beq', 'deliver')
    a(ppc.lhz(27, 2, 31))                                                      # sender
    a.br('bl', 'find')
    a(ppc.cmpwi(3, 0))
    a.br('bne', 'deliver')
    a(ppc.sth(27, 0x8, 1), ppc.mr(3, 30), ppc.addi(4, 1, 0x8))
    a.call(OBJECT_BY_ID)
    a(ppc.cmpwi(3, 0))
    a.br('beq', 'nearest')
    a.call(CAST_WEAPON)
    a(ppc.cmpwi(3, 0))
    a.br('beq', 'nearest')
    a(ppc.lhz(27, 0x2c8, 3))                                                   # weapon owner
    a.br('bl', 'find')
    a(ppc.cmpwi(3, 0))
    a.br('bne', 'deliver')
    a.label('nearest')                    # f5 = best squared distance, r29 = its slot
    a(ppc.li(26, 0))
    a.label('loop')
    a(ppc.slwi(5, 26, 2), ppc.add(5, 5, 30), ppc.lwz(5, 0x14f4, 5))
    for k in range(3):
        a(ppc.lfs(2, 0x50 + 4 * k, 5), ppc.lfs(3, 0x50 + 4 * k, 28), ppc.fsubs(2, 2, 3),
          ppc.fmuls(4, 2, 2) if k == 0 else ppc.fmadds(4, 2, 2, 4))
    a(ppc.cmpwi(26, 0))
    a.br('beq', 'take')
    a(ppc.fcmpo(4, 5))
    a.br('bge', 'next')
    a.label('take')
    a(ppc.fmr(5, 4), ppc.mr(29, 26))
    a.label('next')
    a(ppc.addi(26, 26, 1), ppc.lwz(0, 0x14f0, 30), ppc.cmpw(26, 0))
    a.br('blt', 'loop')
    a.label('deliver')
    a.br('bl', 'swap')
    a(ppc.mr(3, 28), ppc.mr(4, 30), ppc.mr(5, 31), ppc.lwz(12, 0, 28), ppc.lwz(12, 0x18, 12), ppc.mtctr(12), ppc.BCTRL,
      ppc.stw(3, 0x8, 1))
    a.br('bl', 'swap')
    a(ppc.lwz(3, 0x8, 1), *[ppc.lwz(r, 0x10 + 4 * (r - 26), 1) for r in range(26, 32)],
      ppc.lwz(0, F + 4, 1), ppc.mtlr(0), ppc.addi(1, 1, F))
    a.br('b', 'end')
    a.label('find')                       # player slot whose uid == r27 -> r29, r3 = 1; else r3 = 0
    a(ppc.li(7, 0))
    a.label('floop')
    a(ppc.lwz(0, 0x14f0, 30), ppc.cmpw(7, 0))
    a.br('bge', 'fnone')
    a(ppc.slwi(5, 7, 2), ppc.add(5, 5, 30), ppc.lwz(5, 0x14f4, 5), ppc.lhz(6, 8, 5), ppc.cmpw(6, 27))
    a.br('beq', 'fhit')
    a(ppc.addi(7, 7, 1))
    a.br('b', 'floop')
    a.label('fhit')
    a(ppc.mr(29, 7), ppc.li(3, 1), ppc.BLR)
    a.label('fnone')
    a(ppc.li(3, 0), ppc.BLR)
    a.label('swap')                       # exchange slot 0 and slot r29 of players and player states
    a(ppc.cmpwi(29, 0), ppc.BEQLR, ppc.slwi(5, 29, 2), ppc.add(5, 5, 30))
    for base in (0x14f4, 0x1504):
        a(ppc.lwz(6, base, 30), ppc.lwz(7, base, 5), ppc.stw(7, base, 30), ppc.stw(6, base, 5))
    a(ppc.BLR)
    a.label('end')
    return a.done()

# Each code: words = {addr: (orig, new, what)}; hooks = [(site, orig, body, what)]
CODES = {
    'A': dict(
        name='Echoes co-op: keep inventory on spawn (respawns keep, start items only once)',
        words={
            0x8010d01c: (0x901d0050, ppc.NOP, 'SpawnPlayer: keep suit field'),
            0x8010d020: (0x41820058, ppc.b(0x8010d020, 0x8010d078), 'SpawnPlayer: keep powerup block'),
            0x8010d2b0: (0x7f83e378, ppc.b(0x8010d2b0, 0x8010d364), 'SpawnPlayer: skip the loadout loop (keep only)'),
        },
        # The spawn point RSET hooks (0x8020c65c/0x8020c67c -> raise_only) are gone (2026-10-24): RSET is the
        # story's own loadout change (the item loss in Temple Grounds, the Landing Site intro's missiles), and the
        # vanilla handler already applies it to every player, so co-op now matches single player there.
        hooks=[(0x8010d580, 0x38600001, loadout_first_spawn_only(), 'Arrival: spawn loadout only on the first spawn')]),
    'B': dict(
        name='Echoes co-op: campaign session (Sidehopper Station starts or continues the co-op save file; no time/kill limit)',
        words={
            0x8010d560: (0xd01f0008, ppc.NOP, 'match timer: do not advance elapsed'),
            0x800764bc: (0x41800040, ppc.b(0x800764bc, 0x800764fc), 'kill limit: never reached'),
        },
        hooks=[(TELEPORTER_MSG, 0x9421ffe0, retarget(), 'WorldTeleporter: Sidehopper -> campaign'),
               (MATCH_START_END, 0x396100e0, load_coop_save(), 'Match start: load the co-op save file'),
               (0x8010d478, 0x4bfff5d9, respawn_with_partner(), 'SpawnPlayer: clear death fade, respawn next to partner')]),
    'D': dict(
        name='Echoes co-op: full-screen cinematics (every cinematic camera runs on P1 and takes the whole screen)',
        # The game already draws one full-screen viewport when P1's camera manager is in a cinematic AND that
        # cinematic camera has a multiplayer flag (+0x208 bit 1); campaign cameras lack the flag, so the
        # cinematic played in P1's half only. Use the plain "cinematic active" test (FUN_8005c1d0) instead of
        # FUN_8005c1ec at both places that decide it: the top-level draw and the viewport layout.
        words={
            # Camera message handler FUN_801dafbc: a camera started/stopped by a player goes to that player's
            # camera manager (sm+0x1514 + 4 * index). Use player 1's manager for everyone, as single player
            # does, so a cinematic player 2 triggers (e.g. a save station pad) plays full screen above.
            **{a: (0x5460103a, ppc.li(0, 0), 'Camera handler: player-sent camera -> player 1 manager')
               for a in (0x801db154, 0x801db22c, 0x801db2b8, 0x801db310)},
        },
        hooks=[(0x8005c1d0, 0xa0830012, cinematic_check_shared(), 'Players 2-4 held during cinematics too'),
               (0x800e88a4, 0x4bf73949, single_view_or_message(), 'Draw: one full-screen view (P1 cinematic or message box)'),
               (0x8024b584, 0x4be10c69, single_view_or_message(), 'Viewport layout: full screen (P1 cinematic or message box)'),
               (0x800e8654, 0x2c040000, message_hud_pass(), 'HUD pass: still drawn with a message box open'),
               (0x800e870c, 0x800314f0, message_hud_count(), 'HUD pass: only player 1 HUD with a message box open')]),
    'E': dict(
        name='Echoes co-op: Scan Visor works and no friendly fire',
        words=scan_in_multiplayer(),
        hooks=[(0x80149ee8, 0x48101615, scan_text_box(), 'Scan: show scan text in the message box under MP'),
               (0x8024abb4, 0x2c030000, message_state_gate(), 'Pause state: allow message box/close under MP'),
               (0x800ddc28, 0x7c070000, message_input_any_remote(), 'Message box: any Wii Remote can advance it'),
               (MODIFY_DAMAGE, 0x9421ffa0, no_friendly_fire(), 'Damage: players cannot hurt players'),
               (0x80166aac, 0x5460843e, scan_search_fallback(), 'Scan Visor: no id-buffer target -> nearest scannable at the aim, else lock-on')]),
    'C': dict(
        name='Echoes co-op: shared room transitions (any player opens the next room; others follow)',
        words={},
        hooks=[(0x801e6bf8, 0x480000f5, any_player_crossed(), 'Dock: any player crossing moves everyone'),
               (0x801db1f8, 0x807f1514, stop_camera_for_every_player(), 'Camera stop: check every player camera manager')]),
    'F': dict(
        name='Echoes co-op: enemies fight the nearest player (not only player 1)',
        words={},
        hooks=[(0x80240be8, 0x4bfffdad, nearest_player_think(), 'Entity loop: nearest player is players[0] during enemy Think'),
               (0x80240d50, 0x4e800421, nearest_player_think(prethink=True), 'PreThink loop: same during enemy PreThink'),
               (0x8024b3d0, 0x4e800421, relevant_player_message(), 'Messages (immediate): relevant player is players[0] for enemies'),
               (0x80244c70, 0x4e800421, relevant_player_message(), 'Messages (queued, incl. damage): same')]),
    'G': dict(
        name='Echoes co-op: save stations work (needs code E for the save screen)',
        # SaveStation special function (type 7) ACTN handler FUN_8020e800: `if (IsMultiplayer(mgr)) return;`
        # before refilling energy and opening the save screen (SetPauseState(mgr, 5)).
        words={0x8020e83c: (0x408200a4, ppc.NOP, 'Save station: also under MP rules')},
        hooks=[]),
    'H': dict(
        name='Echoes co-op: item pickups go to every player (charge beam pulls them in as in single player)',
        # Pickup Think FUN_801f7d04: a charging player pulls pickups in from 30 units in single player but only
        # 12 under MP rules (`bl IsMP` @0x801f88f8 picks -0x7594(r13) = 12.0 over -0x7598(r13) = 30.0).
        words={0x801f8900: (0x4182000c, ppc.b(0x801f8900, 0x801f890c), 'Charge beam: pull pickups from 30 units (SP range)')},
        hooks=[(PICKUP_TOUCH_AFTER_GRANT, 0x1c19000c, shared_pickup(), 'Pickup: give it to every player')]),
    'I': dict(
        name='Echoes co-op: scan progress is shared',
        words={},
        hooks=[(0x8014a474, 0x48023f29, shared_scan_time(), 'Scan update: progress to every player'),
               (0x80149e8c, 0x48024511, shared_scan_time(), 'Scan state: progress to every player'),
               (0x8014a2d4, 0x480240c9, shared_scan_time(), 'Scan update (player target reset): every player')]),
    'K': dict(
        name='Echoes co-op: map screen works (button 1, player 1)',
        # The HUD only builds its map/pause frame object (+0x30) for one player, and the map button is ignored
        # with 2+ players; forcing it open without the object crashed (session 23). Build it, accept the button
        # (and state 1 in code E's pause gate), load the HUD textures the map uses, then fix three drawing issues.
        words={0x80156e88: (0x41820034, ppc.NOP, 'HUD ctor: always build the map frame object (+0x30)'),
               0x80241854: (0x40820058, ppc.NOP, 'Map button: also with 2+ players'),
               0x8024188c: (0x40820020, ppc.NOP, 'Map button: any controller (not only controller 0)'),
               0x80159598: (0x418202a8, ppc.NOP, 'HUD: load the single-player HUD texture list (map icons)')},
        hooks=[(0x801577fc, 0x9421fe80, hud_on_top_begin(), 'Paused HUD (scan text, menus): drawn over the world'),
               (0x80245504, 0x9421fea0, hud_on_top_end(), 'World draw: end of the paused-HUD depth override'),
               (0x803ec8d0, 0x8122cf08, zmode_hud_on_top(), 'GXSetZMode: ALWAYS while the paused HUD draws'),
               (0x80157b84, 0x2c050000, map_only_when_open(), 'Map: no corner minimap with 2+ players'),
               (0x80157c14, 0x4e800421, map_skip_backdrop(), 'Map: no backdrop panel with 2+ players'),
               (0x80157c84, 0x38800006, map_depth_always(), 'Map: ignore world depth with 2+ players'),
               (0x80157cbc, 0x48210579, map_placement(), 'Map: usable placement with 2+ players')]),
    'L': dict(
        name='Echoes co-op: shared lives (Kill Limit / 5 per player, refilled when saving; 0 = off)',
        words={},
        hooks=[(0x80076428, 0x7fa4eb78, lives_respawn_gate(), 'Respawn: needs a life; all down ends the match'),
               (0x80076454, 0x9b370004, lives_spend(), 'Respawn: spend a life, show the pool'),
               (0x8024ac68, 0x9421ffd0, lives_refill_on_save(), "'Saved' message after a save: refill the pool"),
               (0x80076414, 0xc0170000, lives_unfade_partners(), 'Dead player: keep the other players lit'),
               (0x8024b844, 0x57e0103a, lives_spectate(), 'Out of lives: show the view of a player who is up'),
               (0x800dd9cc, 0x57e01838, lives_spectate_hud(), 'Out of lives: and the HUD of that player')]),
    'J': dict(
        name='Echoes co-op: upgrades given by scripts go to every player',
        words={},
        hooks=[(e, 0x9421ffe0, every_player_special_function(e), f'Special function {31 + k} (power-up): every player')
               for k, e in enumerate(SF_GRANT_HANDLERS)]
              + [(STATE_GRANT_SITE, 0x807e1504, every_player_state_grant(), 'Script grant on ZERO: every player')]),
}


BODY_BASE = 0x93700000                     # MEM2 above the game's arena (hi 0x935e0000) and the IOS heap
BODY_END = 0x93800000                      # (0x935e0000-0x93600000): IOS-reserved, unused under Dolphin's HLE IOS


def far_jump(target):
    """r12 = target; bctr. r12 is free right after every hook site (checked) and inside every body's exit."""
    return [*ppc.load32(12, target), ppc.mtctr(12), 0x4e800420]


INLINE_SITES = {0x800ddc28, 0x80157c14, 0x80157c84}                # CTR is live there (the dispatcher's bdnz loop): keep the body in the
                                           # Gecko list, where Dolphin's C2 returns with a plain branch


def hook_layout(keys=None):
    """[(key, site, orig, body address, body words, what)]: bodies packed from BODY_BASE (0x20-aligned), each
    followed by a far jump back to site + 4. INLINE_SITES are left out (they stay C2 bodies)."""
    out, addr = [], BODY_BASE
    for key in (keys or CODES):
        for site, orig, body, what in CODES[key]['hooks']:
            if site in INLINE_SITES:
                continue
            words = list(body) + far_jump(site + 4)
            out.append((key, site, orig, addr, words, what))
            addr = (addr + 4 * len(words) + 0x1f) & ~0x1f
    assert addr <= BODY_END, f'hook bodies end at {addr:#x}, past {BODY_END:#x}'
    return out


def gecko_lines(*keys):
    """One Gecko code (one gate, one terminator) holding the given features: the gate, single-word patches,
    and per hook a C2 stub that far-jumps to its body in MEM2 (onframe_lines() writes the bodies). Dolphin's
    code list must end below 0x80003000; keeping only stubs there leaves room for more features."""
    lines = [f'20{a & 0x1ffffff:06X} {v:08X}' for a, v in GATE.items()]    # nested 32-bit "if equal" (AND)
    for key in keys:
        for a, (_, new, _) in CODES[key]['words'].items():
            lines.append(f'04{a & 0x1ffffff:06X} {new:08X}')
    stubs = [(site, far_jump(addr)) for _, site, _, addr, _, _ in hook_layout(keys)]
    stubs += [(site, list(body)) for key in keys for site, _, body, _ in CODES[key]['hooks'] if site in INLINE_SITES]
    for site, words in stubs:
        words = words + ([ppc.NOP, 0] if len(words) % 2 == 0 else [0])    # last word: the C2 branch-back slot
        lines.append(f'C2{site & 0x1ffffff:06X} {len(words) // 2:08X}')
        lines += [f'{words[i]:08X} {words[i + 1]:08X}' for i in range(0, len(words), 2)]
    lines.append('E0000000 80008000')                                    # full terminator: end all ifs
    return lines


def onframe_lines(*keys):
    """Dolphin [OnFrame] patch lines writing every hook body to MEM2 (Dolphin applies them on the host each
    frame, so their size does not count against the Gecko code area). Inert until a gated stub jumps there."""
    return [f'0x{addr + 4 * i:08X}:dword:0x{w:08X}' for _, _, _, addr, words, _ in hook_layout(keys)
            for i, w in enumerate(words)]


COMBINED_NAME = 'Echoes co-op (all features: ' + ', '.join(CODES) + ')'

# Difficulty. FUN_800bc668 (the difficulty getter behind every damage scale) returns the save's difficulty
# (global *(r13-0x6440)+0x80: 0 Normal, 1 Veteran, 2 Hypermode) only when the game mode tag (gs+0x148 vt+0x44)
# is 'SNGL'; co-op runs as 'DTHM', so `li r3,1` at 0x800bc6a0 made it Veteran. One code per choice, rewriting
# that immediate; with none enabled co-op stays on Veteran. Scales by difficulty (tweak +0x48/+0x4c and two
# constants): damage to Samus x0.5 / x1 / x1.53 (FUN_800bc334), Samus's damage to enemies x1.3 / x1 / x0.5
# (FUN_800bc39c, via FUN_80292110 in the damage builder FUN_802429ec).
DIFFICULTY_SITE, DIFFICULTY_ORIG = 0x800bc6a0, 0x38600001
DIFFICULTIES = {'Normal': (0, 'damage taken x0.5, dealt x1.3'),
                'Veteran': (1, 'damage taken and dealt x1, as on GameCube Normal'),
                'Hypermode': (2, 'damage taken x1.53, dealt x0.5')}
DEFAULT_DIFFICULTY = 'Hypermode'


def difficulty_name(name):
    return f'Echoes co-op difficulty: {name} (enable one; none = Veteran)'


def difficulty_lines(name):
    lines = [f'20{a & 0x1ffffff:06X} {v:08X}' for a, v in GATE.items()]
    lines.append(f'04{DIFFICULTY_SITE & 0x1ffffff:06X} {ppc.li(3, DIFFICULTIES[name][0]):08X}')
    return lines + ['E0000000 80008000']
BODIES_NAME = 'Echoes co-op hook code (needed by the Gecko code of the same name)'
CODE_LIST_START, CODE_LIST_END = 0x80002338, 0x80003000    # Dolphin's list after its code handler


def enabled_keys():
    return [k for k in CODES if k not in os.environ.get('COOP_WITHOUT', '')]   # debugging aid: leave features out


def combined_lines():
    lines = gecko_lines(*enabled_keys())
    end = CODE_LIST_START + 8 + 8 * (len(lines) + len(difficulty_lines(DEFAULT_DIFFICULTY))) + 8
    assert end <= CODE_LIST_END, f'combined code ends at {end:#x}, past {CODE_LIST_END:#x}: Dolphin would drop it'
    return lines


DOLPHIN_USER = os.environ.get('DOLPHIN_USER', os.path.join(os.environ.get('APPDATA', ''), 'Dolphin Emulator'))   # User folder (portable: <dolphin>/User)
OUR_SECTIONS = ('[Gecko]', '[Gecko_Enabled]', '[OnFrame]', '[OnFrame_Enabled]')


def install_gecko():
    ini = os.path.join(DOLPHIN_USER, 'GameSettings', 'R3ME01.ini')
    os.makedirs(os.path.dirname(ini), exist_ok=True)
    keep = []
    if os.path.exists(ini):                     # drop any previous copy of our sections, keep the rest
        skip = False
        for line in open(ini).read().splitlines():
            if line.startswith('['):
                skip = line.strip() in OUR_SECTIONS
            if not skip:
                keep.append(line)
    body = ['[Gecko]', f'${COMBINED_NAME}', '*Gated on rs5mp2_p.dol being resident; R3ME01 rev 0 only.']
    body += [f'*{k}: {c["name"]}' for k, c in CODES.items()] + combined_lines()
    for name, (_, what) in DIFFICULTIES.items():
        body += [f'${difficulty_name(name)}', f'*{what}'] + difficulty_lines(name)
    body += ['[Gecko_Enabled]', f'${COMBINED_NAME}', f'${difficulty_name(DEFAULT_DIFFICULTY)}']
    body += ['[OnFrame]', f'${BODIES_NAME}'] + onframe_lines(*enabled_keys())
    body += ['[OnFrame_Enabled]', f'${BODIES_NAME}']
    open(ini, 'w').write('\n'.join([l for l in keep if l.strip()] + body) + '\n')
    cfg = os.path.join(DOLPHIN_USER, 'Config', 'Dolphin.ini')
    s = open(cfg).read()
    if 'EnableCheats' in s:
        s = s.replace('EnableCheats = False', 'EnableCheats = True')
    else:
        s = s.replace('[Core]\n', '[Core]\nEnableCheats = True\n', 1)
    open(cfg, 'w').write(s)
    print(f'wrote {ini}; EnableCheats = True in {cfg}')


def resident(d):
    return all(d.u32(a) == v for a, v in GATE.items())


def _branch_target(site, word):
    if word >> 26 != 18:
        return None
    li = word & 0x03fffffc
    return (site + (li - 0x04000000 if li & 0x02000000 else li)) & 0xffffffff


def check(d):
    state = {}
    for key, c in CODES.items():
        for a, (orig, new, what) in c['words'].items():
            cur = d.u32(a)
            state[a] = 'patched' if cur == new else 'original' if cur == orig else f'OTHER {cur:08x}'
            print(f'  {key} {a:#x} {cur:08x} {state[a]:9s} {what}')
        for site, orig, _, what in c['hooks']:
            cur = d.u32(site)
            t = _branch_target(site, cur)
            state[site] = (f'hooked->{t:08x}' if t is not None and 0x80001800 <= t < 0x80003000
                           else 'original' if cur == orig else f'OTHER {cur:08x}')
            print(f'  {key} {site:#x} {cur:08x} {state[site]:17s} {what}')
    cur = d.u32(DIFFICULTY_SITE)
    picked = [n for n, (v, _) in DIFFICULTIES.items() if cur == ppc.li(3, v)]
    print(f'  difficulty {DIFFICULTY_SITE:#x} {cur:08x} {picked[0] if picked else "OTHER"}')
    return state


LIVE_CAVE = 0x80002800


def live(seconds):
    """Python stand-in for the code handler, for cheats-OFF runs only."""
    import dolmem
    d = dolmem.Dolphin(writable=True)
    end = time.time() + seconds
    while time.time() < end:
        if resident(d) and any(d.u32(a) == orig for c in CODES.values() for a, (orig, _, _) in c['words'].items()):
            cave = LIVE_CAVE
            for c in CODES.values():
                for a, (orig, new, _) in c['words'].items():
                    if d.u32(a) == orig:
                        d.w32(a, new)
                for site, orig, body, _ in c['hooks']:
                    code = list(body) + [ppc.b(cave + 4 * len(body), site + 4)]
                    d.write(cave, b''.join(struct.pack('>I', w) for w in code))
                    d.w32(site, ppc.b(site, cave))
                    cave += 4 * len(code)
            print(f'[{time.strftime("%H:%M:%S")}] rs5mp2 resident: patches applied (caves {LIVE_CAVE:#x}..{cave:#x})',
                  flush=True)
        time.sleep(0.005)


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'gecko-all'
    if cmd == 'gecko':
        for key in (sys.argv[2:] or CODES):
            print(f'${CODES[key]["name"]}')
            print('\n'.join(gecko_lines(key)))
    elif cmd == 'gecko-all':
        print(f'${COMBINED_NAME}')
        print('\n'.join(combined_lines()))
    elif cmd == 'onframe-all':
        print(f'${BODIES_NAME}')
        print('\n'.join(onframe_lines(*enabled_keys())))
    elif cmd == 'install-gecko':
        install_gecko()
    elif cmd == 'live':
        live(float(sys.argv[sys.argv.index('--seconds') + 1]) if '--seconds' in sys.argv else 3600)
    elif cmd == 'unpatch':
        # restore original words (turn Dolphin cheats off first or the codes re-apply next frame)
        import dolmem
        d = dolmem.Dolphin(writable=True)
        assert resident(d), 'rs5mp2 not resident'
        for c in CODES.values():
            for a, (orig, _, _) in c['words'].items():
                d.w32(a, orig)
            for site, orig, _, _ in c['hooks']:
                d.w32(site, orig)
        check(d)
    elif cmd == 'check':
        import dolmem
        d = dolmem.Dolphin()
        print(f'rs5mp2 resident: {resident(d)}')
        check(d)
