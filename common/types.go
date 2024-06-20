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
	Tag       byte // 0x70
	LimitsRef *Limits
}

type MemType struct {
	LimitsRef *Limits
}

type Limits struct {
	Tag byte
	Min uint32
	Max uint32
}

type GlobalType struct {
	ValType ValType
	Mutable bool
}

type Expr struct {
	Data []byte
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

const (
	LimitsFlagNoMax  byte = 0x00
	LimitsFlagHasMax byte = 0x01
)

const (
	NotMutable byte = 0x00
	Mutable    byte = 0x01
)
