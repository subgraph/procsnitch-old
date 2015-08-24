package procsnitch

import (
	"testing"
	"fmt"
	"github.com/stretchr/testify/assert"
)

func Test_FindSocketsByDestination(t *testing.T) {
	socket := "23: 00000000:B65D 08080808:0050 02 00000001:00000000 01:000002E4 00000003  1000        0 75236 2 0000000000000000 800 0 0 1 7"
	FindSocketsByDestination("")
}
func Test_FindExecutablePathByInode1(t *testing.T) {
	sockets, err := GetSocketList(TCP)
	assert.NoError(t, err)
	socket, err := ParseSocketStatus(sockets[0])
	path, err := FindExecutablePathByInode(socket.Inode)
	assert.NoError(t, err)
}

func Test_ParseSocketStatus1(t *testing.T) {
	socket := "1: 00000000:006F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 14365 1 0000000000000000 100 0 0 10 0"
	_, err := ParseSocketStatus(socket)
	assert.NoError(t, err)
}

