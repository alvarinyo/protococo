" Vim syntax file
" Language: Protococo DSL
" Maintainer: protococo
" Latest Revision: 2024

if exists("b:current_syntax")
  finish
endif

" Keywords
syn keyword cocoKeyword version endian const enum message extends match nextgroup=cocoIdentifier skipwhite
syn keyword cocoLayerKw layer
syn keyword cocoType u8 u16 u32 u64 i8 i16 i32 i64 bytes string pad bits bit
syn keyword cocoEndian le be
syn keyword cocoModifier cstr
syn keyword cocoAttribute display doc

" Identifiers
syn match cocoIdentifier "\<[a-zA-Z_][a-zA-Z0-9_]*\>" contained

" User-defined types: identifier followed by field name (TypeName fieldName pattern)
" Uses \ze to match only the type, not the field name
" Note: This is pattern-based and may highlight non-existent types
syn match cocoUserType "\<[a-zA-Z_][a-zA-Z0-9_]*\>\ze\s\+[a-zA-Z_][a-zA-Z0-9_]*\>"

" Numbers
syn match cocoNumber "\<\d\+\>"
syn match cocoHexNumber "\<0x[0-9a-fA-F]\+\>"
syn match cocoBinNumber "\<0b[01]\+\>"

" Strings
syn region cocoString start='"' end='"' skip='\\"'

" Comments
syn match cocoComment "//.*$"
syn region cocoBlockComment start="/\*" end="\*/"

" Operators
syn match cocoOperator "="
syn match cocoOperator "->"
syn match cocoOperator ":"
syn match cocoOperator "\."

" Brackets
syn match cocoBracket "[\[\]{}()]"

" Special: default marker
syn match cocoDefault "_" contained

" Match branches
syn match cocoArrow "->"

" Highlight links
hi def link cocoKeyword     Keyword
hi def link cocoLayerKw     Keyword
hi def link cocoType        Type
hi def link cocoUserType    Type
hi def link cocoEndian      Constant
hi def link cocoModifier    Special
hi def link cocoIdentifier  Identifier
hi def link cocoNumber      Number
hi def link cocoHexNumber   Number
hi def link cocoBinNumber   Number
hi def link cocoString      String
hi def link cocoComment     Comment
hi def link cocoBlockComment Comment
hi def link cocoAttribute   PreProc
hi def link cocoOperator    Operator
hi def link cocoBracket     Delimiter
hi def link cocoArrow       Operator
hi def link cocoDefault     Special

let b:current_syntax = "coco"
