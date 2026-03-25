# skookum-tools

Decompiler and patcher for SkookumScript compiled binaries (`.sk-bin` + `.sk-sym`). Built for **The Eternal Cylinder** but should work with any game using SkookumScript binary format version 61.

Tested on:
- The Eternal Cylinder (UE 4.24, Day One build rev 2625)
- The Eternal Cylinder (UE 4.27, Steam release rev 2729)

Both builds use the same binary format (version 61). If your game ships with `Classes.sk-bin` and `Classes.sk-sym`, these tools will (probably) work.
If it doesn't, feel free to make an Issue or a PR.

## What's in here

**`sk_decompiler.py`** -- Reads compiled `.sk-bin` + `.sk-sym` and produces readable `.sk` source files. Parses the entire binary with 0 bytes remaining.

**`sk_patcher.py`** -- Patch-based patcher for modding. Loads an original `.sk-bin`, applies your edited `.sk` files on top, and writes a modified binary you can repack into the game. Round-trip verified: all 1,217 script files (Steam build) compile back to byte-identical AST output.

## How SkookumScript binaries work

SK doesn't use bytecode. The `.sk-bin` file is a serialized AST (abstract syntax tree). Every expression in the game's scripts is stored as a typed node with recursive children. The `.sk-sym` file is a lookup table mapping CRC32 hashes to human-readable symbol names.

The decompiler was built by reversing every `from_binary()` method in the [open-source SkookumScript plugin](https://github.com/EpicSkookumScript/SkookumScript-Plugin) (UE 4.24) into equivalent Python.

## Usage

### Decompile

```bash
python sk_decompiler.py <Classes.sk-bin> <Classes.sk-sym> [output_dir]
```

Output goes into two folders:
- `cpp-bound/` -- C++ bound method stubs (signatures only, no editable logic)
- `script/` -- Script-defined methods and coroutines (the actual game logic)

Each method becomes its own `.sk` file, organized by class hierarchy.

### Patch (mod)

```bash
python sk_patcher.py <original.sk-bin> <original.sk-sym> <mod_dir> [--output <out.sk-bin> <out.sk-sym>]
```

The patcher loads the original binary, then looks in `mod_dir` for any `.sk` files you've changed. Only include files you've actually edited. Everything else stays as-is from the original.

`mod_dir` should mirror the decompiler's output structure:

```
my_mod/
  Object/Actor/Pawn/TrebhumBase/
    some_method.sk
    _some_coroutine.sk
```

If `--output` isn't specified, it writes to `<original>.patched.sk-bin` and `<original>.patched.sk-sym`.

## File naming

- `method_name.sk` -- instance method
- `_coroutine_name.sk` -- coroutine (the leading `_` is part of the SK naming convention)
- `!method_nameC.sk` -- class method
- `!Data.sk` -- data member declarations

Characters unsafe on Windows are escaped in filenames: `?` becomes `-Q`, `!` becomes `-E`, `*` becomes `-S`, etc.

## Requirements

Python 3.8+. No external dependencies.

## Modding (UE4 games)

The full pipeline for modding a UE4 game's SkookumScript:

1. Extract `Classes.sk-bin` and `Classes.sk-sym` from the game's `.pak` file (use [repak](https://github.com/trumank/repak) or similar)
2. Decompile to get readable `.sk` source
3. Copy and edit the files you want to change into a mod directory
4. Patch your mod into the original binary
5. Pack the modified `.sk-bin` + `.sk-sym` into a patch pak and drop it into the game's `Paks/` folder

```bash
# 1. Extract
repak unpack Game.pak

# 2. Decompile
python sk_decompiler.py Classes.sk-bin Classes.sk-sym ./decompiled

# 3. Edit (copy only files you want to change)
mkdir -p my_mod/Object/Actor/Pawn/SomeClass/
cp decompiled/script/Object/Actor/Pawn/SomeClass/_some_coroutine.sk my_mod/Object/Actor/Pawn/SomeClass/
# ... edit the file ...

# 4. Patch
python sk_patcher.py Classes.sk-bin Classes.sk-sym my_mod/ --output patched/Classes.sk-bin patched/Classes.sk-sym

# 5. Pack (UE4 patch pak)
mkdir -p MyMod_P/GameName/Content/SkookumScript/
cp patched/Classes.sk-bin patched/Classes.sk-sym MyMod_P/GameName/Content/SkookumScript/
repak pack --version V11 MyMod_P/ MyMod_P.pak
cp MyMod_P.pak "/path/to/game/Content/Paks/"
```

The `_P` suffix on the pak name tells UE4 to treat it as a patch pak that overrides files in the base pak. Make sure the pak version matches the game's pak version (check with `repak info`).
