package main

import (
	"fmt"
	"github.com/FB124/rsaTcp"
)

func main() {

	//tries to correctly dial the target
	//this will perform the exchange instantly with the target
	rconn, err := rtcp.DialTarget(":99")

	//err handles the dial information
	//makes sure no errors where found correctly
	if err != nil {
		//error handles the information correctly
		fmt.Printf("Error: %s\r\n", err.Error())
		return
	}

	Conn := rconn.MakeConn()

	Conn.Write([]byte("Example message!. this is showing how the message based system works properly"))
}
