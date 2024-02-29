package extn

import (
	"fmt"
	"testing"

	pb "github.com/achuala/kratos-extn/api/gen"
)

func TestHandleSenstiveData(t *testing.T) {
	val := &pb.SensitiveTestData{Name: "Name to be Masked", Secret: "Secret"}
	fmt.Printf("%v\n", val)
	handleSenstiveData(val.ProtoReflect())
	fmt.Printf("%v", val)
}
