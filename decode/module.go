package decode

import (
	"errors"
	"fmt"

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

	// 解析段
	if err = module.decodeSections(bs); err != nil {
		return module, err
	}

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

func (module *Module) decodeSections(bs *common.SliceBytes) (err error) {
	prevSecID := byte(0)

	for bs.Remaining() > 0 {
		var secId byte
		secId, err = bs.ReadByte()
		if err != nil {
			return err
		}

		if secId == SecCustomID {
			// 读取自定义段
			if err = module.decodeCustomSection(bs); err != nil {
				return err
			}
		} else {
			// secId一定是递增的且小于SecDataID
			if secId < prevSecID || secId > SecDataID {
				return errors.New("invalid section id")
			}
			// 解析非自定义段
			// 读取当前段的section长度
			_, _, err := common.DecodeInt32(bs)
			if err != nil {
				return err
			}

			if err = module.decodeNonSection(secId, bs); err != nil {
				return err
			}
			prevSecID = secId
		}
	}

	return nil
}

func (module *Module) decodeNonSection(secId byte, bs *common.SliceBytes) error {
	// 解析非自定义段
	switch secId {
	case SecTypeID:
		return module.decodeTypeSection(bs)
	case SecImportID:
		return module.decodeImportSection(bs)
	case SecFuncID:
		return module.decodeFunctionSection(bs)
	case SecTableID:
		return module.decodeTableSection(bs)
	case SecMemID:
		return module.decodeMemorySection(bs)
	case SecGlobalID:
		return module.decodeGlobalSection(bs)
	case SecExportID:
		return module.decodeExportSection(bs)
	case SecStartID:
		return module.decodeStartSection(bs)
	case SecElemID:
		return module.decodeElementSection(bs)
	case SecCodeID:
		return module.decodeCodeSection(bs)
	case SecDataID:
		return module.decodeDataSection(bs)
	default:
		return errors.New("invalid section id")
	}
}

func (module *Module) decodeCustomSection(bs *common.SliceBytes) error {
	customSec := CustomSec{}

	// read byte_count
	sectionLen, n, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	// read name
	var nameLen int

	if customSec.Name, nameLen, err = bs.ReadName(); err != nil {
		return err
	}

	// read bytes
	num := int(sectionLen) - n - nameLen
	if customSec.Bytes, err = bs.ReadByteN(num); err != nil {
		return err
	}

	module.CustomSecs = append(module.CustomSecs, customSec)
	return nil
}

// decode Type Section
func (module *Module) decodeTypeSection(bs *common.SliceBytes) error {
	typeCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	module.TypeSec = make([]common.FuncType, 0, typeCount)

	for i := int32(0); i < typeCount; i++ {
		// read type
		tagType, err := bs.ReadByte()
		if err != nil {
			return fmt.Errorf("decodeTypeSection type failed %s", err.Error())
		}
		// 检查是否是TagFuncType
		if tagType != common.TagFuncType {
			return fmt.Errorf("decodeTypeSection invalid type %b", tagType)
		}

		// 解析输入参数
		inputTypes, err := decodeValueTypes(bs)
		if err != nil {
			return fmt.Errorf("decodeTypeSection inputs failed %s", err.Error())
		}

		// 解析函数返回值
		returnTypes, err := decodeValueTypes(bs)
		if err != nil {
			return fmt.Errorf("decodeTypeSection returns failed %s", err.Error())
		}

		funcType := common.FuncType{
			InputTypes:  inputTypes,
			ReturnTypes: returnTypes,
		}

		module.TypeSec = append(module.TypeSec, funcType)
	}
	return nil
}

func decodeValueTypes(bs *common.SliceBytes) ([]common.ValType, error) {
	num, _, err := common.DecodeInt32(bs)
	if err != nil {
		return nil, err
	}
	valTypes := make([]common.ValType, 0, num)
	for i := int32(0); i < num; i++ {
		valType, err := decodeValueType(bs)
		if err != nil {
			return nil, err
		}
		valTypes = append(valTypes, valType)
	}
	return valTypes, nil
}

func decodeValueType(bs *common.SliceBytes) (common.ValType, error) {
	tag, err := bs.ReadByte()
	if err != nil {
		return 0, err
	}
	return common.ValType(tag), nil
}

// decode Import Section
func (module *Module) decodeImportSection(bs *common.SliceBytes) error {
	return nil
}

// decode Function Section
func (module *Module) decodeFunctionSection(bs *common.SliceBytes) error {
	return nil
}

// decode Table Section
func (module *Module) decodeTableSection(bs *common.SliceBytes) error {
	return nil
}

// decode Memory Section
func (module *Module) decodeMemorySection(bs *common.SliceBytes) error {
	return nil
}

// decode Global Section
func (module *Module) decodeGlobalSection(bs *common.SliceBytes) error {
	return nil
}

// decode Export Section
func (module *Module) decodeExportSection(bs *common.SliceBytes) error {
	return nil
}

// decode Start Section
func (module *Module) decodeStartSection(bs *common.SliceBytes) error {
	return nil
}

// decode Element Section
func (module *Module) decodeElementSection(bs *common.SliceBytes) error {
	return nil
}

// decode Code Section
func (module *Module) decodeCodeSection(bs *common.SliceBytes) error {
	return nil
}

// decode Data Section
func (module *Module) decodeDataSection(bs *common.SliceBytes) error {
	return nil
}

func (module *Module) display() string {
	str := ""
	// Magic
	str += fmt.Sprintf("Magic: %d\n", module.Magic)
	// Version
	str += fmt.Sprintf("Version: %d\n", module.Version)
	// TypeSec
	str += module.displayTypeSec()

	return str
}

func (module *Module) displayTypeSec() string {
	displayValType := func(valTypes []common.ValType) string {
		str := "("
		for i, valType := range valTypes {
			if i > 0 {
				str += ", "
			}
			switch valType {
			case common.ValTypeI32:
				str += "i32"
			case common.ValTypeI64:
				str += "i64"
			case common.ValTypeF32:
				str += "f32"
			case common.ValTypeF64:
				str += "f64"
			}
		}
		str += ")"
		return str
	}
	str := ""
	str += fmt.Sprintf("Type[%d]:\n", len(module.TypeSec))
	for i, t := range module.TypeSec {
		str += fmt.Sprintf("  type[%d]: %s->%s\n", i, displayValType(t.InputTypes), displayValType(t.ReturnTypes))
	}
	return str
}
