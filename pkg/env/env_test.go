package env

import (
	"github.com/stretchr/testify/assert"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestGetKernelVersion(t *testing.T) {
	f, err := os.CreateTemp("/tmp", "mock_kernel_version-"+strconv.Itoa(time.Now().Nanosecond()))
	if err != nil {
		assert.Fail(t, "Create temp version file failed")
		return
	}
	defer f.Close()

	_, err = f.Write([]byte("5.9.1-1-rt19-MANJARO"))
	if err != nil {
		assert.Fail(t, "Write failed")
		return
	}

	assert.Equal(t, "5.9.1", getKernelVersion(f.Name()))
}
