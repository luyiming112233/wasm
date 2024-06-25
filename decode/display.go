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
	// FuncSec
	str += module.displayFuncSec()
	// TableSec
	str += module.displayTableSec()
	// MemSec
	str += module.displayMemorySec()
	// GlobalSec
	str += module.displayGlobalSec()
	// ExportSec
	str += module.displayExportSec()
	// StartSec
	str += module.displayStartSec()
	// ElementSec
	str += module.displayElementSec()
	// CodeSec
	str += module.displayCodeSec()
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
			return fmt.Sprintf("  global[%d]: %s.%s, %s\n", idx, imp.Module, imp.Name, displayGlobalType(imp.Desc.Global))
		default:
			panic("unknown import tag")
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

func displayGlobal(global *Global) string {
	return fmt.Sprintf("{type: %s, init: %s}", displayGlobalType(global.Type), displayExpr(global.Init))
}

func displayGlobalType(globalType *common.GlobalType) string {
	return fmt.Sprintf("{valType: %s, mutable: %t}", displayValType(globalType.ValType), globalType.Mutable)
}

func displayExpr(expr *common.Expr) string {
	return fmt.Sprintf("%v", expr.Data)
}

func (module *Module) displayFuncSec() string {
	str := ""
	str += fmt.Sprintf("Func[%d]:\n", len(module.FuncSec))
	for i, typeIdx := range module.FuncSec {
		str += fmt.Sprintf("  func[%d]: type=%d\n", i, typeIdx)
	}
	return str
}

func (module *Module) displayTableSec() string {
	str := ""
	str += fmt.Sprintf("Table[%d]:\n", len(module.TableSec))
	for i, table := range module.TableSec {
		str += fmt.Sprintf("  table[%d]: %s\n", i, displayLimits(table.LimitsRef))
	}
	return str
}

func (module *Module) displayMemorySec() string {
	str := ""
	str += fmt.Sprintf("Memory[%d]:\n", len(module.MemSec))
	for i, mem := range module.MemSec {
		str += fmt.Sprintf("  memory[%d]: %s\n", i, displayLimits(mem.LimitsRef))
	}
	return str
}

func (module *Module) displayGlobalSec() string {
	str := ""
	str += fmt.Sprintf("Global[%d]:\n", len(module.GlobalSec))
	for i, global := range module.GlobalSec {
		str += fmt.Sprintf("  global[%d]: %s\n", i, displayGlobal(global))
	}
	return str
}

func (module *Module) displayExportSec() string {
	str := ""
	str += fmt.Sprintf("Export[%d]:\n", len(module.ExportSec))
	for i, exp := range module.ExportSec {
		str += fmt.Sprintf("  export[%d]: %s\n", i, displayExportDesc(exp))
	}
	return str
}

func displayExportDesc(export *Export) string {
	switch export.Desc.Tag {
	case ExportTagFunc:
		return fmt.Sprintf("func[%d]=%s", export.Desc.Idx, export.Name)
	case ExportTagTable:
		return fmt.Sprintf("table[%d]=%s", export.Desc.Idx, export.Name)
	case ExportTagMem:
		return fmt.Sprintf("memory[%d]=%s", export.Desc.Idx, export.Name)
	case ExportTagGlobal:
		return fmt.Sprintf("global[%d]=%s", export.Desc.Idx, export.Name)
	default:
		panic("unknown export tag")
	}
}

func (module *Module) displayStartSec() string {
	return fmt.Sprintf("Start: %d\n", module.StartSec)
}

func (module *Module) displayElementSec() string {
	str := ""
	str += fmt.Sprintf("Element[%d]:\n", len(module.ElemSec))

	for i, elem := range module.ElemSec {
		str += fmt.Sprintf("  elem[%d]: %s\n", i, displayElement(elem))
	}

	return str
}

func displayElement(elem *Elem) string {
	str := fmt.Sprintf("table=%d, offset=%s, init=[", elem.Table, displayExpr(elem.Offset))
	for i, init := range elem.Init {
		if i > 0 {
			str += ", "
		}
		str += fmt.Sprintf("%d", init)
	}
	str += "]"
	return str
}

func (module *Module) displayCodeSec() string {
	str := ""
	str += fmt.Sprintf("Code[%d]:\n", len(module.CodeSec))

	for i, code := range module.CodeSec {
		str += fmt.Sprintf("  code[%d]: %s\n", i, displayCode(code))
	}

	return str
}

func displayCode(code *Code) string {
	str := "locals: "

	for i, loc := range code.Locals {
		if i != 0 {
			str += ", "
		}
		str += fmt.Sprintf("[%s x %d]", displayValType(loc.Type), loc.N)
	}

	str += fmt.Sprintf("\nbody: %s", displayExpr(code.Expr))
	fmt.Println(str)

	return str
}
