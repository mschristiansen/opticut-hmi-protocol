# OptiCut S90 HMI — TCP list protocol (port 51000)

**Unofficial, reverse-engineered, partial.** This document describes how the operator
software of a Dimter OptiCut S90 cross-cut saw talks to the saw's HMI process over TCP.
It was derived from packet captures, live tests against a saw, and static disassembly of
the vendor's PC software. It is not vendor documentation; see the disclaimer in the README.

|  |  |
|---|---|
| Machine | Dimter OptiCut S90 (Weinig OptiCom family) |
| Server | the HMI application on the saw (`DDIR_E06_ARML1.run` on the unit this was written against) |
| Peer studied | Weinig **OptiCom Pro PC** (`PCPRO_C06.exe`, version C06) |
| Reference client | [`opticut51000.py`](opticut51000.py) — `upload`, `list`, `fetch` |
| Conformance tests | [`tests/`](tests) |

Every statement carries a tag:

- **[M]** measured — seen in a packet capture, a file on the saw, or a live test;
- **[D]** read from the disassembly of the PC software (static; it was never executed);
- **[I]** inferred — from field values and general cross-cut-saw practice, not from vendor documentation.

An untagged statement is one where all three agree. Other firmware or software versions may
differ.

## 1. Transport

| Item | Value |
|---|---|
| Protocol | TCP, plain; no TLS; no authentication **[M]** |
| Server | the HMI process itself; it listens on 51000, 51001 and 53000, and 51000 is the list channel **[M]** |
| Client role | connect to `<hmi-host>:51000`; several clients may be connected at once, but only one is answered (§3.3) **[M]** |
| Byte order | little-endian **[M]** |
| Text | UTF-8 XML **[M]** |
| Sessions | none: there is no login and no registration message in the client **[D]** |

## 2. Message framing

Every message, in both directions, is a fixed 12-byte header followed by `length` bytes of body.

```
offset  size  type    field
0       4     int32   cmd      command number
4       4     int32   length   body length in bytes (0 = no body)
8       4     int32   x        unused; the PC software sends uninitialised stack here [D][M]
12      len   bytes   body
```

A sender MUST set `x = 0`. A receiver MUST ignore `x`. Messages follow each other with no
separator; a reader splits the stream by `length`.

Examples (hex, header then body):

```
2d000000 00000000 00000000                  cmd 45   keepalive, no body
96000000 d0070000 00000000 <2000 bytes>     cmd 150  list upload, body = list XML
97000000 00000000 00000000                  cmd 151  end of upload
0f000000 20010000 00000000 <288 bytes>      cmd 15   status (HMI -> client)
```

The PC software's own frames carry garbage in `x` (for a keepalive, for instance,
`2d000000 00000000 8e4f4800`); a client of this protocol sends zeros.

## 3. Commands

### 3.1 Client → HMI

The complete list of what the PC software can send, taken from every call site of its single
send routine **[D]** (`0x485e80(body, len, cmd)` on the global client object):

| cmd | body | name | effect |
|---|---|---|---|
| 45 | none | keepalive | none; the PC software sends it on a timer **[M][D]** |
| 150 | list document (§4.2) | upload | the HMI adds the list to its in-memory list set **[M]** |
| 151 | none | end of upload | completes a 150 **[M][D]** |
| 6 | 176-byte struct (§5) | machine-list operation | sub-operation in byte 0: fetch `'e'`, delete `'i'`, toggle `'j'` **[D]** |

There is no rename, no "set active list" and no delete-by-name command **[D]**.

### 3.2 HMI → client

| cmd | body | content |
|---|---|---|
| 15 | 288 bytes binary | machine status (counters, a date string); layout not decoded **[M]** |
| 70 | XML `<PRODLIST><PRODUCT><NAME>…<BREITE>…<DICKE>…<CUTLIST><ITEM><AKTIV>…<LAENGE>…<SOLL>…<IST>…<ID>…<BEMERK>…` | progress of the active list; lengths in µm (`2142000` = 2142 mm) **[M]** |
| 6 | 122 200 bytes, sub-operation `'d'` | the machine list directory, §3.4 **[M]** |
| 6 | other sizes, sub-operations `'g'`, `'h'` | not decoded **[D]** |
| 1003 | ~20 KB binary | not decoded **[M]** |
| 150 / 151 | list document / 1432-byte statistics sidecar | reply to cmd 6 `'e'`: the list as the HMI holds it now, `Cut` counts included; the sidecar layout is §6 **[M]** |
| 45 | none | keepalive **[M]** |

Receive dispatcher in the PC software: `0x487970`, handling cmds 15, 6, 150, 70 and 151 **[D]**.

### 3.3 The HMI answers one connection at a time

Every connection may *send*; the HMI *answers* only the oldest live one **[M]**.

Observed with two raw clients and the vendor PC software closed: client A connected first,
then B, both sending keepalives. A received ~250 KB in 5 s, B nothing. When A closed, B
started receiving the status stream (cmds 15, 70, 45 at about 5 KB/s) — but no fresh
directory — and a new client C then received nothing while B was served.

Uploads are processed from *any* connection: a list uploaded by a raw client was accepted
while the vendor PC software held the slot **[M]**. There is no registration message **[D]**; the first keepalive is enough to
be queued.

(One capture showed two PC-software connections both receiving. That fits the rule only if
the software replaced one connection with the other; not verified.)

Consequence for a client: it can always upload, but it can read the directory or fetch a list
only while no older connection (typically the vendor PC software) is open. It is not known
whether the directory is re-pushed when a waiting connection inherits the slot (it was not,
once) **[M]**.

### 3.4 The list directory (cmd 6, sub-operation `'d'`, 122 200 bytes) [M]

Pushed to the served client right after its first keepalive. An array of 240-byte records from
offset 0. A record with an empty or non-printable name ends the useful part; the rest of the
buffer is uninitialised memory.

| record offset | size | field |
|---|---|---|
| 32 | 40 | list name, NUL-terminated (so at most 39 characters) |
| 72 | 4 | store: `2` = optimisation list (`.oxml`), `1` = cut sequence (`.pxml`) |
| 76 | 4 | **list id** — the id used by cmd 6 `'e'` and `'i'` |

Ids are assigned by the HMI. Lists present at HMI start are numbered in load order, and lists
uploaded later get the next free number in arrival order; an id is not a row position, and it
grows with each list the HMI creates. Ids the PC software sent for list fetches matched this
table exactly. Parsed by this table the directory is stable: three consecutive pushes were
identical, and it includes lists that were uploaded but not yet saved to disk.

**Ids are reassigned at every HMI start [M]:** after an HMI restart the saved lists were
numbered 1…N again, and the next upload got N+1 (it had been a much higher number before).
Never keep an id across HMI starts; resolve it from a directory read on the same connection.

(An earlier reading of the directory as "racy", and of a resent name as listed twice, came from
scanning names at the wrong offsets.)

## 4. Uploading a list (cmd 150 + 151)

Sequence, as sent by the PC software and by the reference client **[M]**:

```
connect <hmi-host>:51000
-> 45 (empty)                    optional; the PC software's keepalive
   wait 0.5 s
-> 150 <list document>
-> 151 (empty)
   keep the socket open ~20 s, then close        (the proven sequence; no reply arrives)
```

The HMI may close the connection itself right after the 151 (seen once, with a client that
held the socket). A peer close after 151 is normal, not a failure; the list was still
accepted.

Body of 150: the complete list document — the same `<Product>` XML as an `.oxml` file in the
HMI's `DataFiles` directory (§4.2).

- **`<Type>` selects the list type and the store** — see §4.1.
- **No restart [M]:** the list appears in the HMI's list set at once (it showed up in the
  PC software's machine-list column and on the panel). The HMI process id is unchanged; the
  active list and the board in the saw are untouched.
- **No acknowledgement [M]:** nothing is sent back to a raw client. The file appears in
  `DataFiles` only when the HMI saves the list. In one test that happened about 10 s after the
  upload with the socket held ~20 s; in another, with the same hold time, it had not happened
  within 5 minutes. What triggers the save is unknown. Poll; never assume.
- **Existing name [I]:** the PC software asks "overwrite?" before sending a name the machine
  already has (observed by an operator). The HMI is therefore assumed to *replace* the list by
  name and reset its counters, as the panel's own Import does. Not tested directly.
- Lengths in the document are millimetres with three decimals (`<MinLen>2142.000</MinLen>`) **[M]**.

### 4.1 List types

The `<Type>` element decides what the saw does with a list and where it is stored. Every type
uses the same `<Product>` document; they differ in which fields matter.

| `<Type>` | File in `DataFiles` | Directory store (§3.4) | What it is |
|---|---|---|---|
| `MODE_OPTIMIERUNG` (the PC software writes `OPTI` in its own files) | `.oxml` + `.osta` | 2 | **Optimisation list** |
| `MODE_SCHNITTFOLGE` | `.pxml` + `.psta` | 1 | **Cut sequence** (panel: *Schnittfolge*) |
| `MODE_VOROPTI` | `.vxml` (one: `VOROPTI.vxml`) + `VorOpti.sta`/`.dat` | — | **Pre-optimisation** set-up |
| `MODE_SAEGELISTEEXT` | `.sxml` (`OPTIEXTERN.sxml`, `SCANNER.sxml`) | — | **External saw list** (scanner / external optimiser) |

**Optimisation (`MODE_OPTIMIERUNG`) [M][I].** A demand list: each `<Part TYPE="FIX">` is a
length with a `Required` piece count and a `Cut` count of pieces done, plus optional
`TYPE="VAR"` ranges (fill lengths). The saw measures each board and the optimiser chooses
which of the listed lengths to cut from it for the best yield, counting `Cut` up towards
`Required`; `Prio1` weights the choice. The board length is not known in advance, so
`<RawLen>` is 0. The cross-section header (`Width`/`Height`) is the list's nominal section.
This is the type every ordinary order list on the machine had.

**Cut sequence (`MODE_SCHNITTFOLGE`) [M][I].** A fixed pattern: the saw cuts the listed
lengths in the listed order, without optimising. `<RawLen>` can hold the board length (shown
beside the list in the PC software, e.g. "2000.0 mm"), or 0. `Required` was 0 on every part
measured, i.e. no quantity target. Use: a repeating pattern on boards of known length. The PC
software's list filter offers "nur Optimierung" / "nur Schnittfolge" / "Opti && Schnittfolge"
**[D]**.

**Pre-optimisation (`MODE_VOROPTI`) [M][I].** A single machine-level document
(`VOROPTI.vxml`, empty name, all dimensions 0) with its own statistics files; not an order
list. Not decoded.

**External saw list (`MODE_SAEGELISTEEXT`) [M][I].** `OPTIEXTERN.sxml` (all dimensions 0)
and `SCANNER.sxml`: lists fed from outside the HMI's own optimiser. Not decoded.

**Per-part `<Mode>` [M].** Bit 0 is the panel's "Akt." (active) checkbox: 17/19 active,
16/18 inactive. A list sent by a client may reasonably arrive with 16 (inactive), as the
panel's own Import does, leaving the operator to activate the rows. Bit 1 (18/19) is set on
lists the operator has worked; its meaning is not decoded.

### 4.2 The list document (`.oxml`)

```xml
<Product><Name>…</Name><Type>MODE_OPTIMIERUNG</Type><Active>0</Active>
  <Material></Material><Created>dd.mm.yyyy hh:mm.ss</Created><Changed>…</Changed>
  <Version>DXXX</Version><curParSet>0</curParSet>
  <Width>100.000</Width><WidthMin>90.000</WidthMin><WidthMax>110.000</WidthMax>
  <Height>50.000</Height><RawLen>0.000</RawLen><Panel>0</Panel><MeasWidth>0</MeasWidth>
  <Required>0</Required><Cut>0</Cut>
  <Parameter> … </Parameter>
  <GradeList><Grade ID="1"> … </Grade> … 8 grades A–H </GradeList>
  <PartList>
    <Part ID="1" TYPE="FIX"><MinLen>2400.000</MinLen><MaxLen>2400.000</MaxLen>
      <Required>4</Required><Cut>0</Cut><Grade>1</Grade><Mode>16</Mode>
      <Code>label</Code> … </Part>
    <Part ID="0" TYPE="WASTE"> … </Part>          <!-- last, on lists written by the PC software -->
  </PartList></Product>
```

A complete, loadable example is [`examples/hello.xml`](examples/hello.xml).

**Header elements** (all measured against lists on a live saw):

| element | meaning |
|---|---|
| `Name` | the list name; the key the PC software and panel show. At most 39 characters (§3.4) |
| `Type` | §4.1 |
| `Active` | `1` marks the list currently loaded for production; exactly one list has it. A list sent by a client should have `0`, or it takes over the operator's screen **[M]** |
| `Created`, `Changed` | `dd.mm.yyyy hh:mm.ss` (note the dot before the seconds). The HMI rewrites `Changed` whenever it saves the list **[M]** |
| `Version` | software version string written by the HMI |
| `Width`, `Height` | cross-section in mm. `Width` is the *larger* of the two dimensions and `Height` the smaller, on every list measured; taking max/min of a profile's two dimensions makes the result independent of which one is called thickness **[M]** |
| `WidthMin`, `WidthMax` | `90.000` / `110.000` on every list measured, even where `Width` is 80, 101 or 115. These look like machine constants, not a per-list band; copy them verbatim **[M][I]** |
| `RawLen` | board length; `0` for an optimisation list (§4.1) |
| `MeasWidth` | `0` on every list measured |
| `Required`, `Cut` (header) | `0` / `0` on every list measured |
| `Panel`, `curParSet`, `Material` | `0`, `0`, empty on every list measured |

On this machine the cross-section is display and statistics metadata: with `MeasWidth` 0 and
every part's width/thick limits at 0, a cross-cut saw sets no axis from it **[I]**. It is also
live display state — the stored `Width`/`Height` follow whatever the panel last showed, so on a
list that mixes profiles the header section matches none of them **[M]**.

**`<Parameter>`** carries optimiser and display settings. All measured lists had the values in
`examples/hello.xml`: `WasteLenMax`, `WasteMinSort`, `WasteMaxSort`, `WasteBox`,
`WasteBoxOption`, `PreferMaxVarLen`, `Center`, `Tolerance`, `WasteBoardEnd`, `MaxRemainLen`,
`Package`, `PackageX`, `PackageY`, `AdaptRest`, `Schnittzone`, and the panel-column switches
`ShowAktiv`, `ShowBox`, `ShowKennung`, `ShowLaser`, `ShowPrio1`, `ShowPrio2`, `ShowQual`,
`ShowRest`, `ShowSoll`, `ShowWert`. The individual meanings of the optimiser settings are not
decoded.

**`<GradeList>`** holds eight grades, `ID` 1–8, names `A`–`H`, `GradeBits` 1, 2, 4 … 128.
Per grade: `MarkFix`, `FrontTrimFix`, `EndTrimFix`, `MarkVar`, `FrontTrimVar`, `EndTrimVar`.
On the lists measured, grade A carries `FrontTrimFix` and `EndTrimFix` of 20 mm and every
other trim is 0 **[M]**. Consequence: with grade A, the finished length goes into
`MinLen`/`MaxLen` unchanged; the trim is the saw's own, not part of the length **[I]**.

**`<Part>`** — `ID` is a running number, `TYPE` is `FIX`, `VAR` or `WASTE`. Lists written by
the PC software start at ID 1 and end with a `WASTE` part (ID 0, all lengths 0, `Prio1` 0.00).
Lists created by the panel's Import have no `WASTE` part, and their IDs continue from an
arbitrary number; both load **[M]**. Child elements:

| element | meaning |
|---|---|
| `MinLen`, `MaxLen` | length in mm, three decimals. Equal for `FIX`; a range for `VAR` |
| `MinWidth`, `MaxWidth`, `MinThick`, `MaxThick` | `0.000` on every list measured |
| `Prio1`, `Prio2` | weights; default `1.00` / `0.00` on fixed lengths; operators set other weights (0.50–3.00 seen) **[M]** |
| `CountN` | `0` on a fresh list |
| `Required` | the piece count wanted (the panel's "required" column) |
| `Cut` | pieces done (the panel's "actual" column). A fresh list has `0`; setting it to `Required` presents the part as already cut **[M]** |
| `Value` | `0.00` |
| `Grade` | grade ID, 1–8 |
| `Mode` | §4.1; `16` on a fresh row |
| `PrintInfo`, `LaserInfo`, `ReqType`, `Box`, `BoxOption` | `0` on every list measured |
| `Code` | the panel's label column: free UTF-8 text, accented characters included. Used by operators to group rows |
| `PartNo` | empty on every list measured |

Rows with `Required` 0 are legal (an operator can use a short filler row as a visual
separator between groups; the optimiser ignores a row with nothing required) **[M][I]**.

**Panel Import sorts rows by `Code`**, descending as text, keeping file order inside a group,
when a list is imported on the panel from an `.IMP` file; a list loaded from an `.oxml` at HMI
start is taken as written, not sorted **[M]**. Whether a list received over TCP is sorted is
not known.

## 5. cmd 6 client body — machine-list operations [D]

A 176-byte struct. Only these fields are meaningful; everything else is uninitialised memory
(the `-1` at +4 and `12` at +0x10 seen in captures are stack leftovers).

| offset | size | field |
|---|---|---|
| 0 | 1 | operation: `'e'` 0x65 fetch list to PC · `'i'` 0x69 **delete** · `'j'` 0x6a toggle lengths |
| 8 | 4 | flag; the PC software sends 1 for fetches **[M]** |
| 0x0C | 4 | **list id** from the directory, §3.4 **[M]** |

The operation is chosen by the Qt slot that sends it (moc table of the PC software):

### 5.1 `'e'` — fetch (`on_btnSave_clicked`) [M][D]

Sent when the user presses the save icon above the machine-list column. Fields: `+8` is item
role 0x104, `+0xC` is item role 0x101 (the list id).

Proven from a raw client: body = 176 zero bytes with `'e'` at 0, `1` at +8, the id at +0xC →
the HMI answers cmd `150` with the list document as it holds it now (`Cut` counts included)
and cmd `151` with the 1432-byte statistics sidecar (§6). Read-only. The client must be the
HMI's served connection (§3.3).

### 5.2 `'i'` — delete (`on_btnLoeschenMaschine_clicked`) [D][M]

Deletes a machine list **by id, never by name** (§3.4). Layout: `+8` is item role 0x104 (the
list-kind flag, 0 or 1), `+0xC` is item role 0x101 (the list id). Bytes 1–3, `+4` and `+0x10…`
are uninitialised.

- The PC software sends it only after a confirm dialog. It refuses locally, with *"letzte
  Liste kann nicht gelöscht werden"*, when the operation would delete the last list of that
  kind, and branches away when item role 0x108 is set.
- Captured deletes carried the kind flag and an id from the directory; the ids grew with each
  list the HMI created.
- Ids are reassigned at every HMI start (§3.4), so an id remembered from before a restart
  points at a different list.
- A stale or guessed id deletes whichever list currently owns it. **This repository's client
  does not implement delete.**

### 5.3 `'j'` — toggle lengths (`LaengeToggeln_clicked`) [D]

Sends three PC-side global values (at `0x54b040`, `0x54b044`, and a flag `0x54b048 == 0`).
It is not a list operation; its effect on the HMI is not decoded.

### 5.4 HMI → client sub-operations

The HMI uses cmd 6 towards the client too: `'d'` (0x64) is the 122 200-byte directory block
(§3.4), `'g'` (0x67) and `'h'` (0x68) are not decoded **[D]**.

## 6. The statistics sidecar (`.osta`, 1432 bytes)

Every list has a sidecar of statistics (`.osta` for optimisation lists, `.psta` for cut
sequences). All values little-endian; the layout is the same in every `.osta`/`.sta` file,
including the machine-level `Statistic1.sta` **[M]**.

| offset | type | panel field |
|---|---|---|
| 48 | int32 | seconds — the panel's per-list clock |
| 72 | int32 | number of boards |
| 232 | double | waste, m |
| 240 | double | raw timber of quality 1, m |
| 304 | double | **raw timber total, m** |
| 476 | int32 | number of fixed lengths (also readable at 508) |
| 560 | double | cut product, m |
| 952 | double | waste total (waste + good timber), m |
| 1272 | int32 | number of cuts |

The sidecar of a list that has never run is all zeros except **byte 7 = 0x01** **[M]**: that
is the template a client can write for a list it creates itself (not needed for TCP upload,
where the HMI makes its own).

The counters satisfy `cuts = boards + fixed lengths (+ variable lengths)`: one cut opens a
board and one is made per piece taken off it; the tail falls free as good timber and costs no
cut. The residue (actual cuts minus this sum) was always ≥ 0, never negative, which suggests
*extra* cuts — a defect cut-out or a second end trim **[M][I]**. Do not build on the residue.

Statistics are per-list lifetime, not per day, and the machine-level file is an
operator-resettable slot with its own epoch: compare deltas, never levels.

## 7. Memory versus files on disk

The HMI holds its lists in memory and saves them to its `DataFiles` directory. Observations
that matter to anyone moving lists around:

- **An `.oxml`/`.osta` pair copied into `DataFiles` does not appear on the panel until the
  HMI starts again** **[M]**: the files are the application's *output* store, read at start-up.
- At start-up the HMI rewrites every list it loaded (all files within a couple of seconds,
  `<Changed>` moving to the restart time). That rewrite is also a cheap proof that a list was
  taken into memory **[M]**.
- Lists are also rewritten at run time: the list being cut is saved repeatedly (about every
  two minutes while cutting), so `sum(<Cut>)` of the active list is a live count of finished
  pieces **[M]**.
- A list received over TCP (§4) is in memory at once but reaches `DataFiles` only when the
  HMI next saves; the trigger is unknown.
- Weinig's file-manager tool for the saw (OpticomExplorer) is built on libssh2 (SFTP/SCP plus
  remote shell commands to stop and start the application); it does not speak this protocol
  **[D]**.
- The panel's own Import reads `.IMP` files (semicolon-separated rows) from a configurable
  path. An autoimport that polls such a path exists and overwrites the *active* list — avoid
  enabling it **[M]**.

## 8. Not supported / not known

- Rename, set-active-list, delete-by-name: not in the client **[D]**.
- Whether the directory is re-sent when a waiting connection inherits the served slot.
- The layouts of cmd 15, cmd 1003 and cmd 6 `'g'`/`'h'`, and the effect of `'j'`.
- What makes the HMI save an uploaded list to disk (§4).
- The HMI's behaviour on an uploaded name that already exists (§4) — inferred, not measured.
- Behaviour with malformed lists. Assume the HMI does not validate them.

## 9. Recommendations for client authors

1. Send only cmds 45, 150, 151 and cmd 6 `'e'` (read-only fetch) unless you have a reason and
   a test saw. Treat `'i'` (delete) and `'j'` as dangerous: `'i'` removes whatever list owns
   the id you send, so resolve the id from a directory received on the *same* connection,
   immediately before, and never reuse an old one.
2. Send `x = 0` in every header; ignore `x` on receive. Treat a peer close after the 151 as
   normal (§4).
3. Before an upload, check the list name against the directory when you can get it (§3.3), and
   refuse — or ask the operator to confirm — a name the saw already has. If you cannot read
   the directory, keep your own record of what you sent, because a fresh upload has no file
   on disk yet (§4).
4. Write that record *before* the 150 frame goes out, so no list ever leaves without a row.
5. Treat "sent" as "delivered", not "saved". Confirm through the directory (when the vendor
   software is closed), through `DataFiles`, or on the panel.
6. Send lists inactive (`<Active>0</Active>`, parts `Mode` 16) so a received list never takes
   over the operator's screen; let the operator activate it.
7. Never set `Cut` above 0 on a list you create: that presents pieces as already cut.
8. Keep list names to 39 characters or fewer, ASCII, no characters that are illegal in a file
   name (the name becomes one).
9. Keep the socket open for ~20 s after the last frame, as the vendor software does; closing
   at once is untested.
10. Do not run this against a production saw without the operator's agreement. The protocol
    has no authentication and the HMI does not validate what it receives.

## 10. How this was derived

- **Packet captures** of the vendor PC software talking to the HMI: uploads of several lists
  (both optimisation lists and cut sequences), deletes of two lists, and list fetches. Header
  and body layouts in §2–§5 are checked byte for byte against those captures.
- **Live tests** with a raw client: uploads of a one-row list and of a two-length list, both
  of which appeared on the panel with the HMI process unchanged; directory reads and a list
  fetch with the vendor software closed; the oldest-connection behaviour of §3.3 with two and
  three raw clients.
- **Static disassembly** (`objdump -d`, never executed) of `PCPRO_C06.exe`: the send routine
  at `0x485e80`, the receive dispatcher at `0x487970`, the call sites of every command, and
  the Qt slot/operation mapping of cmd 6 (§5).
- **Files on the saw**: dozens of `.oxml`/`.osta` pairs, used to pin down the document and
  sidecar layouts (§4.2, §6).
