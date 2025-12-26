# Syntax Highlighting for Protococo (.coco files)

This directory contains syntax highlighting definitions for `.coco` protocol specification files.

## Vim/Neovim

### Installation

Copy the syntax files to your vim runtime directory:

```bash
mkdir -p ~/.vim/syntax
mkdir -p ~/.vim/ftdetect
cp syntax/coco.vim ~/.vim/syntax/
cp ftdetect/coco.vim ~/.vim/ftdetect/
```

For Neovim:
```bash
mkdir -p ~/.config/nvim/syntax
mkdir -p ~/.config/nvim/ftdetect
cp syntax/coco.vim ~/.config/nvim/syntax/
cp ftdetect/coco.vim ~/.config/nvim/ftdetect/
```

### Features

- Keywords: `version`, `endian`, `message`, `enum`, `layer`, `extends`, `match`
- Types: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, `bytes`, `string`, `bits`, `bit`, `pad`
- Attributes: `[display: ...]`
- Enum references: `EnumType.MEMBER`
- Comments: `#` and `//`
- Hex numbers: `0x0800`
- Pattern matching syntax
- Bitfield syntax

## Bat (batcat)

[bat](https://github.com/sharkdp/bat) is a cat clone with syntax highlighting.

### Installation

1. Install bat if you haven't already:
   ```bash
   # Ubuntu/Debian
   sudo apt install bat

   # Arch
   sudo pacman -S bat

   # macOS
   brew install bat
   ```

2. Copy the syntax file to bat's syntaxes directory:
   ```bash
   mkdir -p ~/.config/bat/syntaxes
   cp syntax/coco.sublime-syntax ~/.config/bat/syntaxes/
   ```

3. Build bat's cache:
   ```bash
   batcat cache --build
   # or if your system uses 'bat':
   bat cache --build
   ```

### Usage

```bash
batcat file.coco
bat --style=plain file.coco  # No line numbers/decorations
```

### Features

The bat syntax highlighter supports:
- All language keywords and constructs
- Type system (primitives, enums, custom types)
- Endianness modifiers (`:be`, `:le`)
- Display attributes (`[display: mac]`, `[display: ipv4]`, etc.)
- Enum value references (`EtherType.IPV4`)
- Arithmetic expressions in size specifiers
- Pattern matching syntax (`->`, `_`)
- Bitfield definitions
- Comments (`#` and `//`)
- Numeric literals (hex, decimal)

## Testing

After installation, test with example files:

```bash
# Vim
vim protocols/ip.coco

# Bat
batcat protocols/ip.coco
```

## File Structure

```
syntax/
├── README.md              # This file
├── coco.vim              # Vim syntax highlighting
└── coco.sublime-syntax   # Bat syntax highlighting (Sublime Text format)

ftdetect/
└── coco.vim              # Vim filetype detection
```
