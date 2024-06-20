package decode

import (
	"fmt"

	"github.com/luyiming112233/wasm/common"
)

func (module *Module) display() string {
	str := ""
	// Magic
	str += fmt.Sprintf("Magic: %d\n", module.Magic)
	// Version
	str += fmt.Sprintf("Version: %d\n", module.Version)
	// TypeSec
	str += module.displayTypeSec()
	// ImportSec
	str += module.displayImportSec()
	return str
}

func (module *Module) displayTypeSec() string {
	displayValType := func(valTypes []common.ValType) string {
		str := "("
		for i, valType := range valTypes {
			if i > 0 {
				str += ", "
			}
			str += displayValType(valType)
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

func (module *Module) displayImportSec() string {
	str := ""
	str += fmt.Sprintf("Import[%d]:\n", len(module.ImportSec))

	displayImport := func(imp *Import, idx int) string {
		switch imp.Desc.Tag {
		case ImportTagFunc:
			return fmt.Sprintf("  func[%d]: %s.%s, sig=%d\n", idx, imp.Module, imp.Name, imp.Desc.FuncType)
		case ImportTagTable:
			return fmt.Sprintf("  table[%d]: %s.%s, %s\n", idx, imp.Module, imp.Name, displayLimits(imp.Desc.Table.LimitsRef))
		case ImportTagMem:
			return fmt.Sprintf("  memory[%d]: %s.%s, %s\n", idx, imp.Module, imp.Name, displayLimits(imp.Desc.Mem.LimitsRef))
		case ImportTagGlobal:
			return fmt.Sprintf("  global[%d]: %s.%s, %s\n", idx, imp.Module, imp.Name, displayGrobalType(imp.Desc.Global))
		default:
			// todo lym 实现其他类型
			panic("todo lym")
		}
	}

	for i, imp := range module.ImportSec {
		str += displayImport(imp, i)
	}
	return str
}

func displayValType(valType common.ValType) string {
	switch valType {
	case common.ValTypeI32:
		return "i32"
	case common.ValTypeI64:
		return "i64"
	case common.ValTypeF32:
		return "f32"
	case common.ValTypeF64:
		return "f64"
	default:
		panic(fmt.Sprintf("<unknown value_type %d>", int8(valType)))
	}
}

func displayLimits(limit *common.Limits) string {
	return fmt.Sprintf("{min: %d, max: %d}", limit.Min, limit.Max)
}

func displayGrobalType(globalType *common.GlobalType) string {
	return fmt.Sprintf("{valType: %s, mutable: %t}", displayValType(globalType.ValType), globalType.Mutable)
}
