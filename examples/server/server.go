package main

import (
	"encoding/hex"
	"fmt"
	"rsaTcp"
)

func main() {

	//creates a new rTcp listener
	//this will broadcast the listener to the host given in the args
	listener, err := rtcp.NewListener(":99")

	//makes sure no errors happened
	//this will error log any errors which happened
	if err != nil {
		//logs the error to the err stream and ends proc
		fmt.Printf("Err: %s\r\n", err.Error())
		return
	}

	//gets the fingerprint for the server properly
	//this will allow us to get information properly
	Fingerprint, err := listener.Fingerprint()

	//makes sure no errors happened
	//this will error log any errors which happened
	if err != nil {
		//logs the error to the err stream and ends proc
		fmt.Printf("Err %s\r\n", err.Error())
		return
	}

	//renders information to the stream
	//renders the host port and the fingerprint
	fmt.Printf("[debug] Server: [%s]\r\n", listener.Host)
	fmt.Printf("[debug] Server Public Fingerprint %s\r\n", hex.EncodeToString(Fingerprint))

	for {
		//accepts the incoming connection properly
		//this will accept and perform the handshake with the client
		rconn, err := listener.AcceptConnection()

		//err handles the statement properly
		//this will allow us to properly error handle the information
		if err != nil {
			//logs the error to the err stream and continues the proc
			fmt.Printf("[debug] client error: %s\r\n",err.Error())
			continue
		}

		//creates a proper interface for the client
		conn := rconn.MakeConn()

		fmt.Printf("VALID CONNECTION FROM %s\r\n", conn.Remote().RemoteAddr())

		Value, err := conn.Reader(1024)

		fmt.Println(string(Value), err)

		fmt.Println(conn.Written)

	}
}
