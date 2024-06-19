package common

import (
	"encoding/binary"
	"io"
)

type SliceBytes struct {
	bs       []byte
	pc       int
	teeIndex int
}

func NewSliceBytes(bt []byte) *SliceBytes {
	return &SliceBytes{
		bs:       bt,
		pc:       -1,
		teeIndex: -1,
	}
}

func (bt *SliceBytes) ReadByte() (byte, error) {
	bt.pc++
	if bt.pc >= len(bt.bs) {
		return 0, io.EOF
	}
	return bt.bs[bt.pc], nil
}

func (bt *SliceBytes) ReadByteAsInt32() (int32, error) {
	b, err := bt.ReadByte()
	return int32(b), err
}

func (bt *SliceBytes) ReadByteAsInt64() (int64, error) {
	b, err := bt.ReadByte()
	return int64(b), err
}

func (bt *SliceBytes) ReadByteN(n int) ([]byte, error) {
	if bt.pc+n >= len(bt.bs) {
		return []byte{}, io.EOF
	}

	res := bt.bs[bt.pc+1 : bt.pc+n+1]
	bt.pc += n

	return res, nil
}

func (bt *SliceBytes) ReadUint32() (uint32, error) {
	data, err := bt.ReadByteN(4)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(data), nil
}

func (bt *SliceBytes) Remaining() int {
	return len(bt.bs) - bt.pc
}

func (bt *SliceBytes) ReadName() (string, int, error) {
	// 读取name的长度
	nameLen, _, err := DecodeInt32(bt)
	if err != nil {
		return "", 0, err
	}
	// 读取name
	name, err := bt.ReadByteN(int(nameLen))
	if err != nil {
		return "", 0, err
	}
	return string(name), int(nameLen), nil
}
