package main

import (
	"fmt"
	"log"

	"github.com/subgraph/procsnitch"
)

func main() {
	sockets, err := procsnitch.GetSocketList(procsnitch.TCP)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%5s\t%20s\t%20s\t%20s\t%s\n",
		"#", "LocalAddr", "RemoteAddr", "Connection Status", "Executable")
	for i, socket := range sockets {
		socketStatus, err := procsnitch.ParseSocketStatus(socket)
		if err != nil {
			log.Fatal(err)
		}
		executablePath, err := procsnitch.FindExecutablePathByInode(socketStatus.Inode)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%5d\t%20s\t%20s\t%20s\t%s\n", i+1, socketStatus.LocalAddr,
			socketStatus.RemoteAddr, socketStatus.Status, executablePath)
	}
}
