package decode

import (
	"errors"
	"github.com/luyiming112233/wasm/common"
)

const (
	MagicNumber = 0x6D736100 // `\0asm`
	Version     = 0x00000001 // 1
)

var (
	ErrInvalidMagicNumber = errors.New("invalid magic number")
	ErrInvalidVersion     = errors.New("invalid version header")
)

const (
	SecCustomID = iota
	SecTypeID
	SecImportID
	SecFuncID
	SecTableID
	SecMemID
	SecGlobalID
	SecExportID
	SecStartID
	SecElemID
	SecCodeID
	SecDataID
)

const (
	ImportTagFunc   = 0
	ImportTagTable  = 1
	ImportTagMem    = 2
	ImportTagGlobal = 3
)
const (
	ExportTagFunc   = 0
	ExportTagTable  = 1
	ExportTagMem    = 2
	ExportTagGlobal = 3
)

type Module struct {
	Magic      uint32
	Version    uint32
	CustomSecs []CustomSec
	TypeSec    []common.FuncType
	ImportSec  []Import
	FuncSec    []common.TypeIdx
	TableSec   []common.TableType
	MemSec     []common.MemType
	GlobalSec  []Global
	ExportSec  []Export
	StartSec   *common.FuncIdx
	ElemSec    []Elem
	CodeSec    []Code
	DataSec    []Data
}

// DecodeModule decodes a `raw` module from io.Reader whose index spaces are yet to be initialized
func DecodeModule(bs *common.SliceBytes) (*Module, error) {
	module := &Module{}
	var err error

	// 解析Magic
	module.Magic, err = bs.ReadUint32()
	if err != nil {
		return nil, err
	}
	if module.Magic != MagicNumber {
		return nil, ErrInvalidMagicNumber
	}

	// 解析Version
	module.Version, err = bs.ReadUint32()
	if err != nil {
		return nil, err
	}
	if module.Version != Version {
		return nil, ErrInvalidVersion
	}

	// todo 解析段

	return module, nil
}

type CustomSec struct {
	Name  string
	Bytes []byte // TODO
}

type Import struct {
	Module string
	Name   string
	Desc   ImportDesc
}
type ImportDesc struct {
	Tag      byte
	FuncType common.TypeIdx    // tag=0
	Table    common.TableType  // tag=1
	Mem      common.MemType    // tag=2
	Global   common.GlobalType // tag=3
}

type Global struct {
	Type common.GlobalType
	Init common.Expr
}

type Export struct {
	Name string
	Desc ExportDesc
}
type ExportDesc struct {
	Tag byte
	Idx uint32
}

type Elem struct {
	Table  common.TableIdx
	Offset common.Expr
	Init   []common.FuncIdx
}

type Code struct {
	Locals []Locals
	Expr   common.Expr
}
type Locals struct {
	N    uint32
	Type common.ValType
}

type Data struct {
	Mem    common.MemIdx
	Offset common.Expr
	Init   []byte
}

func (code Code) GetLocalCount() uint64 {
	n := uint64(0)
	for _, locals := range code.Locals {
		n += uint64(locals.N)
	}
	return n
}
