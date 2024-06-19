package common

type (
	TypeIdx   = uint32
	FuncIdx   = uint32
	TableIdx  = uint32
	MemIdx    = uint32
	GlobalIdx = uint32
	LocalIdx  = uint32
	LabelIdx  = uint32
)

type FuncType struct {
	InputTypes  []ValType
	ReturnTypes []ValType
}

type TableType struct {
	// todo
}

type MemType struct {
	// todo
}

type GlobalType struct {
	// todo
}

type Expr struct {
	// todo
}

type ValType byte

const (
	ValTypeI32 ValType = 0x7F // i32
	ValTypeI64 ValType = 0x7E // i64
	ValTypeF32 ValType = 0x7D // f32
	ValTypeF64 ValType = 0x7C // f64
)

const (
	TagFuncType byte = 0x60
)
