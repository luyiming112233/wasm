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

const TableTypeTag = 0x70

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
	TypeSec    []*common.FuncType
	ImportSec  []*Import
	FuncSec    []common.TypeIdx
	TableSec   []common.TableType
	MemSec     []common.MemType
	GlobalSec  []*Global
	ExportSec  []*Export
	StartSec   common.FuncIdx
	ElemSec    []*Elem
	CodeSec    []*Code
	DataSec    []*Data
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
	FuncType common.TypeIdx     // tag=0
	Table    *common.TableType  // tag=1
	Mem      *common.MemType    // tag=2
	Global   *common.GlobalType // tag=3
}

type Global struct {
	Type *common.GlobalType
	Init *common.Expr
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
	Offset *common.Expr
	Init   []common.FuncIdx
}

type Code struct {
	Locals []Locals
	Expr   *common.Expr
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

	module.TypeSec = make([]*common.FuncType, 0, typeCount)

	for i := int32(0); i < typeCount; i++ {
		funcType, err := decodeFuncType(bs)
		if err != nil {
			return err
		}
		module.TypeSec = append(module.TypeSec, funcType)
	}
	return nil
}

func decodeFuncType(bs *common.SliceBytes) (*common.FuncType, error) {
	// read type
	tagType, err := bs.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("decodeTypeSection type failed %s", err.Error())
	}
	// 检查是否是TagFuncType
	if tagType != common.TagFuncType {
		return nil, fmt.Errorf("decodeTypeSection invalid type %b", tagType)
	}

	// 解析输入参数
	inputTypes, err := decodeValueTypes(bs)
	if err != nil {
		return nil, fmt.Errorf("decodeTypeSection inputs failed %s", err.Error())
	}

	// 解析函数返回值
	returnTypes, err := decodeValueTypes(bs)
	if err != nil {
		return nil, fmt.Errorf("decodeTypeSection returns failed %s", err.Error())
	}

	return &common.FuncType{
		InputTypes:  inputTypes,
		ReturnTypes: returnTypes,
	}, nil
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
	importCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	module.ImportSec = make([]*Import, 0, importCount)
	for i := int32(0); i < importCount; i++ {
		imp, err := decodeImport(bs)
		if err != nil {
			return err
		}
		module.ImportSec = append(module.ImportSec, imp)
	}

	return nil
}

func decodeImport(bs *common.SliceBytes) (*Import, error) {
	imp := &Import{}
	// module name
	moduleName, _, err := bs.ReadName()
	if err != nil {
		return nil, err
	}
	imp.Module = moduleName

	// name
	name, _, err := bs.ReadName()
	if err != nil {
		return nil, err
	}
	imp.Name = name

	// tag
	tag, err := bs.ReadByte()
	if err != nil {
		return nil, err
	}
	imp.Desc.Tag = tag

	switch tag {
	case ImportTagFunc:
		// func type
		funcType, err := decodeTypeIdx(bs)
		if err != nil {
			return nil, err
		}
		imp.Desc.FuncType = funcType
	case ImportTagTable:
		// table type
		tableType, err := decodeTableType(bs)
		if err != nil {
			return nil, err
		}
		imp.Desc.Table = tableType
	case ImportTagMem:
		// mem type
		memType, err := decodeMemType(bs)
		if err != nil {
			return nil, err
		}
		imp.Desc.Mem = memType
	case ImportTagGlobal:
		// global type
		globalType, err := decodeGlobalType(bs)
		if err != nil {
			return nil, err
		}
		imp.Desc.Global = globalType
	default:
		return nil, errors.New("invalid import tag")
	}

	return imp, nil
}

func decodeTypeIdx(bs *common.SliceBytes) (common.TypeIdx, error) {
	idx, _, err := common.DecodeInt32(bs)
	if err != nil {
		return 0, err
	}
	return common.TypeIdx(idx), nil
}

func decodeTableType(bs *common.SliceBytes) (*common.TableType, error) {
	tableTag, err := bs.ReadByte()
	if err != nil {
		return nil, err
	}
	if tableTag != TableTypeTag {
		return nil, fmt.Errorf("decodeTableType failed invalid table type tag %b", tableTag)
	}

	limit, err := decodeLimitsType(bs)
	if err != nil {
		return nil, err
	}

	return &common.TableType{
		Tag:       tableTag,
		LimitsRef: limit,
	}, nil
}

func decodeMemType(bs *common.SliceBytes) (*common.MemType, error) {
	limit, err := decodeLimitsType(bs)
	if err != nil {
		return nil, err
	}

	return &common.MemType{
		LimitsRef: limit,
	}, nil
}

func decodeLimitsType(bs *common.SliceBytes) (*common.Limits, error) {
	tag, err := bs.ReadByte()
	var minVal, maxVal uint32
	if err != nil {
		return nil, err
	}

	switch tag {
	case common.LimitsFlagNoMax:
		minVal, _, err = common.DecodeUint32(bs)
		if err != nil {
			return nil, err
		}
	case common.LimitsFlagHasMax:
		minVal, _, err = common.DecodeUint32(bs)
		if err != nil {
			return nil, err
		}
		maxVal, _, err = common.DecodeUint32(bs)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("decodeLimitsType failed invalid limits tag %b", tag)
	}

	return &common.Limits{
		Tag: tag,
		Min: minVal,
		Max: maxVal,
	}, nil
}

func decodeGlobalType(bs *common.SliceBytes) (*common.GlobalType, error) {
	globalType := &common.GlobalType{}
	valType, err := decodeValueType(bs)
	if err != nil {
		return nil, err
	}
	globalType.ValType = valType

	mutable, err := bs.ReadByte()
	if err != nil {
		return nil, err
	}
	globalType.Mutable = mutable == common.Mutable

	return globalType, nil
}

func decodeExpr(bs *common.SliceBytes) (*common.Expr, error) {
	data := make([]byte, 0)
	for {
		op, err := bs.ReadByte()
		if err != nil {
			return nil, err
		}
		if op == common.ExprEnd {
			break
		}
		data = append(data, op)
	}

	return &common.Expr{Data: data}, nil
}

// decode Function Section
func (module *Module) decodeFunctionSection(bs *common.SliceBytes) error {
	funcCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	module.FuncSec = make([]common.TypeIdx, 0, funcCount)
	for i := int32(0); i < funcCount; i++ {
		typeIdx, _, err := common.DecodeInt32(bs)
		if err != nil {
			return err
		}
		module.FuncSec = append(module.FuncSec, common.TypeIdx(typeIdx))
	}

	return nil
}

// decode Table Section
func (module *Module) decodeTableSection(bs *common.SliceBytes) error {
	tableCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	if tableCount != 1 {
		return fmt.Errorf("decodeTableSection failed invalid table count %d", tableCount)
	}

	module.TableSec = make([]common.TableType, 0, tableCount)
	for i := int32(0); i < tableCount; i++ {
		tableType, err := decodeTableType(bs)
		if err != nil {
			return err
		}
		module.TableSec = append(module.TableSec, *tableType)
	}

	return nil
}

// decode Memory Section
func (module *Module) decodeMemorySection(bs *common.SliceBytes) error {
	memoryCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	if memoryCount != 1 {
		return fmt.Errorf("decodeMemorySection failed invalid memory count %d", memoryCount)
	}

	module.MemSec = make([]common.MemType, 0, memoryCount)
	for i := int32(0); i < memoryCount; i++ {
		memType, err := decodeMemType(bs)
		if err != nil {
			return err
		}
		module.MemSec = append(module.MemSec, *memType)
	}

	return nil
}

// decode Global Section
func (module *Module) decodeGlobalSection(bs *common.SliceBytes) error {
	globalCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	module.GlobalSec = make([]*Global, 0, globalCount)
	for i := int32(0); i < globalCount; i++ {
		globalType, err := decodeGlobalType(bs)
		if err != nil {
			return err
		}

		initExpr, err := decodeExpr(bs)
		if err != nil {
			return err
		}

		module.GlobalSec = append(module.GlobalSec, &Global{
			Type: globalType,
			Init: initExpr,
		})
	}

	return nil
}

// decode Export Section
func (module *Module) decodeExportSection(bs *common.SliceBytes) error {
	exportCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	module.ExportSec = make([]*Export, 0, exportCount)

	for i := int32(0); i < exportCount; i++ {
		export, err := decodeExport(bs)
		if err != nil {
			return err
		}
		module.ExportSec = append(module.ExportSec, export)
	}

	return nil
}

func decodeExport(bs *common.SliceBytes) (*Export, error) {
	export := &Export{}

	name, _, err := bs.ReadName()
	if err != nil {
		return nil, err
	}
	export.Name = name

	tag, err := bs.ReadByte()
	if err != nil {
		return nil, err
	}
	export.Desc.Tag = tag

	idx, _, err := common.DecodeUint32(bs)
	if err != nil {
		return nil, err
	}
	export.Desc.Idx = idx

	return export, nil
}

// decode Start Section
func (module *Module) decodeStartSection(bs *common.SliceBytes) error {
	start, _, err := common.DecodeUint32(bs)
	if err != nil {
		return err
	}

	module.StartSec = start
	return nil
}

// decode Element Section
func (module *Module) decodeElementSection(bs *common.SliceBytes) error {
	elementCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	module.ElemSec = make([]*Elem, 0, elementCount)
	for i := int32(0); i < elementCount; i++ {
		elem, err := decodeElement(bs)
		if err != nil {
			return err
		}
		module.ElemSec = append(module.ElemSec, elem)
	}

	return nil
}

func decodeElement(bs *common.SliceBytes) (*Elem, error) {
	elem := &Elem{}

	tableIdx, _, err := common.DecodeUint32(bs)
	if err != nil {
		return nil, err
	}
	elem.Table = common.TableIdx(tableIdx)

	offset, err := decodeExpr(bs)
	if err != nil {
		return nil, err
	}
	elem.Offset = offset

	funcCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return nil, err
	}

	elem.Init = make([]common.FuncIdx, 0, funcCount)
	for i := int32(0); i < funcCount; i++ {
		funcIdx, _, err := common.DecodeUint32(bs)
		if err != nil {
			return nil, err
		}
		elem.Init = append(elem.Init, common.FuncIdx(funcIdx))
	}

	return elem, nil
}

// decode Code Section
func (module *Module) decodeCodeSection(bs *common.SliceBytes) error {
	codeCount, _, err := common.DecodeInt32(bs)
	if err != nil {
		return err
	}

	module.CodeSec = make([]*Code, 0, codeCount)
	for i := int32(0); i < codeCount; i++ {
		code, err := decodeCode(bs)
		if err != nil {
			return err
		}
		module.CodeSec = append(module.CodeSec, code)

	}
	return nil
}

func decodeCode(bs *common.SliceBytes) (*Code, error) {
	// decode byte_count
	ss, _, err := common.DecodeUint32(bs)
	if err != nil {
		if err != nil {
			return nil, fmt.Errorf("get the size of code segment: %d err %w", ss, err)
		}
	}

	code := &Code{}

	// locals
	var localSize int
	localCount, size, err := common.DecodeUint32(bs)
	if err != nil {
		return nil, err
	}
	localSize += size

	locals := make([]Locals, 0, localCount)
	for i := uint32(0); i < localCount; i++ {
		n, size, err := common.DecodeUint32(bs)
		if err != nil {
			return nil, err
		}
		localSize += size

		valType, err := decodeValueType(bs)
		if err != nil {
			return nil, err
		}
		localSize += 1

		locals = append(locals, Locals{N: n, Type: valType})
	}
	code.Locals = locals

	// expr
	exprLen := int(ss) - localSize
	if exprLen < 0 {
		return nil, fmt.Errorf("invalid expr len %d", exprLen)
	}

	exprData, err := bs.ReadByteN(exprLen)
	if err != nil {
		return code, err
	}
	code.Expr = &common.Expr{
		Data: exprData,
	}

	return code, nil
}

// decode Data Section
func (module *Module) decodeDataSection(bs *common.SliceBytes) error {
	return nil
}
