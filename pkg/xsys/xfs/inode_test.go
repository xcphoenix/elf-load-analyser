package xfs

import (
	"fmt"
	"testing"
)

func TestFindPath(t *testing.T) {
	path, err := FindPath(3015077)
	fmt.Println(path, err)
}
