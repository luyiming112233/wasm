package decode

import (
	"fmt"
	"github.com/luyiming112233/wasm/common"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestModule(t *testing.T) {
	buf, err := ioutil.ReadFile("../testdata/wasm/ch01_hw.wasm")
	assert.Nil(t, err)

	sb := common.NewSliceBytes(buf)
	module, err := DecodeModule(sb)
	if module != nil {
		fmt.Println(module.display())
	}

	assert.Nil(t, err)

	//data, err := json.Marshal(module)
	//fmt.Println(string(data))
}
