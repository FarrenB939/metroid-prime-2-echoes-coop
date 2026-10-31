# Echoes co-op

Split-screen co-op for the **Metroid Prime 2: Echoes** campaign, for 2-4 players on one PC, in
**Metroid Prime Trilogy NTSC-U (`R3ME01`) on Dolphin**. It starts from Echoes' own versus mode,
which already runs several Samus players in one world, and fixes everything that assumed one
player: rooms, saves, scanning, cutscenes, enemies, items and story events.

No game files are included. You need your own copy of Metroid Prime Trilogy.

Write-up, research notes and test log: [Co-op Anything: Metroid Prime 2: Echoes](https://github.com/cranebeaker/coop-anything/tree/main/games/metroid-prime-2-echoes).

## Requirements

- Metroid Prime Trilogy, NTSC-U, `R3ME01` revision 0. Echoes' executable `rs5mp2_p.dol` must have
  SHA-256 `5b68271fd75ff1bd48986874d6f9112fc8299a1c93c6ce459fa1a83b8ebeb2b2`. Other regions and the
  GameCube Echoes won't work (the codes stay inactive).
- Dolphin (tested with 2609a). Use mainline Dolphin, not PrimeHack: PrimeHack only drives player 1.
- A controller per player. `WiimoteNew.ini` here maps two Xbox controllers.

## Install

1. In Dolphin, open the user folder (File > Open User Folder).
2. Copy `echoes-coop-R3ME01.ini` to `GameSettings\R3ME01.ini` there. If that file exists, back it up
   first or merge the four sections into it.
3. Config > General: tick **Enable Cheats**.
4. Optional, two Xbox controllers: with Dolphin closed, back up `Config\WiimoteNew.ini` and copy
   `WiimoteNew.ini` over it. Wii Remotes 1 and 2 become an emulated Wii Remote + Nunchuk on XInput
   pads 0 and 1. For 3-4 players, set up Wii Remotes 3 and 4 yourself.
5. Right-click the game > Properties. Under Gecko Codes, "Echoes co-op (all features ...)" and
   "Echoes co-op difficulty: Hypermode" should be ticked; under Patches, "Echoes co-op hook code".

The ini has two parts that must both be on: the Gecko code (small, only active while Echoes is
loaded) and the `[OnFrame]` patch that writes the hook code to unused memory at 0x93700000.

## Play

Main menu > Metroid Prime 2: Echoes > **Multiplayer**. Everyone joins, then pick the game for the
number of players, **Deathmatch** (Kill Limit sets the lives, below) and **Sidehopper Station**.
That starts the campaign instead of the arena.

- Co-op uses the Trilogy's **third Echoes save file**. Empty: a new game at the Landing Site.
  Saved: it continues at the save station. Everyone gets player 1's health and items.
  To play an existing single-player run in co-op, copy it to the third slot first (Copy Slot on the
  Trilogy's Game Select screen); the original stays untouched.
- Progress is kept only by saving at a save station or Samus's gunship.

## What works

- **Rooms:** any player can lead through a door. The others can walk through while it's open; anyone still
  behind it when it closes is brought through and appears beside the leader (two Morph Balls fit a tunnel
  side by side). Big doors work too. Elevators and portals take everyone.
- **Items:** pickups, expansions and upgrades go to every player. Story events that change items
  (the item loss in Hive Chamber B) apply to everyone, as in single player. Respawns keep items.
- **Scan Visor:** every player can scan, scan progress is shared, and any player can page the text.
- **Cutscenes and message boxes** play full screen from player 1's view; everyone is held in place
  during cutscenes. **Start (Menu on Xbox) skips a cutscene**, the opening included, even the first time.
- **Enemies and bosses** go after the nearest player, not only player 1.
- **No friendly fire.**
- **Map:** button 1 (View on Xbox) on any controller; any player can use it.
- **Data Network:** button 2 (Menu on Xbox) on any controller opens the single-player pause screen (Scans %,
  Items %, Inventory, Logbook) full screen; the player who opened it controls it and closes it (2 again, or B
  at the top).
- **Save stations and the gunship** work.

## Lives

The team shares a pool of lives, shown in the HUD's centre counters. Set it with **Kill Limit**
before choosing Sidehopper Station: lives per player = Kill Limit / 5 (default 10 = 2 each;
0 = unlimited respawns). Each respawn spends one. With none left, a fallen player watches a
teammate's view until someone saves (answering Yes), which refills the pool and brings them back.
If everyone is down with no lives left, the match ends; start Sidehopper Station again to continue
from the last save.

## Difficulty

Hypermode by default. To change it, tick exactly one "Echoes co-op difficulty" code under Gecko Codes:

| Code | Damage Samus takes | Damage Samus deals |
|---|---|---|
| Normal (the Trilogy's easy mode) | x0.5 | x1.3 |
| Veteran (the original GameCube Normal) | x1 | x1 |
| Hypermode (the original Hard mode) | x1.53 | x0.5 |

With none ticked, co-op plays on Veteran. The save file's own difficulty doesn't apply in co-op.

## Controls (`WiimoteNew.ini`, two Xbox controllers)

| Xbox | Wii | Does |
|---|---|---|
| Left stick | Nunchuk stick | move |
| Right stick | pointer | aim and turn (absolute: stick position = pointer position) |
| RT | A | fire, confirm, close message boxes |
| A | B | jump |
| B | C | morph ball |
| LT | Z | lock on |
| LB / RB | - / + | hold for visor / beam select |
| D-pad | D-pad | |
| View | 1 | map |
| Menu | 2 | Data Network (pause); skip a cutscene |

The Xbox A button is the Wii B button: to close a message box, press RT. Pad 0 is player 1, pad 1
player 2 (swap the XInput numbers in the file to change that).

## Known issues

- Only the opening hours have been played through by people; later areas were checked by a test
  harness, not in real play.
- NTSC-U Trilogy only. Local split screen only; Dolphin NetPlay is untested.
- Players have to jump off of save stations to prevent repeated saving
- Menu opens the Data Network instead of the multiplayer "Quit Game?" menu; quit from the Data Network's
  Options.

## Building the codes

`tools/coop_patches.py` is the single source for every code (hooks are written as PowerPC with
`tools/ppc.py`):

```
python tools/coop_patches.py gecko-all       # the combined Gecko code
python tools/coop_patches.py onframe-all     # the [OnFrame] hook bodies
python tools/coop_patches.py install-gecko   # write both into DOLPHIN_USER\GameSettings\R3ME01.ini
```

`DOLPHIN_USER` defaults to `%APPDATA%\Dolphin Emulator`; set it for a portable Dolphin.

The codes were reverse-engineered and tested against a running Dolphin with a set of local
scripts (memory reads and writes, calls into the game, key presses, Ghidra queries) that aren't
published here; the research log is in the Co-op Anything write-up linked above.

## License

MIT, see [LICENSE](LICENSE). Metroid Prime is a trademark of Nintendo; this project is unofficial and ships no game files.

## Credits

Builds on the idea and findings of SubsonicBeatz154's 2019 asset-based Trilogy co-op attempt
([thread](https://forum.metroidconstruction.com/index.php?topic=4942.0)). Made with
[Co-op Anything](https://github.com/cranebeaker/coop-anything).
