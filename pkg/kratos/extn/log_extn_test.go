package extn

import (
	"testing"

	v1 "github.com/achuala/kratos-extn/api/gen/common/v1"
)

func TestHandleSenstiveData(t *testing.T) {
	val := v1.SensitiveTestData{Name: "Name to be Masked", Secret: "Secret"}
	handleSenstiveData(val.ProtoReflect())
}
