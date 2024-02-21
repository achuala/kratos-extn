package extn

import (
	"fmt"
	"testing"

	"github.com/achuala/kratos-extn/api/options"
)

func TestHandleSenstiveData(t *testing.T) {
	val := &options.SensitiveTestData{Name: "Name to be Masked", Secret: "Secret"}
	fmt.Printf("%v\n", val)
	handleSenstiveData(val.ProtoReflect())
	fmt.Printf("%v", val)
}
