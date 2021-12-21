# rsaTcp - lightweight rsa implementaion of asymmetric (Rivest-Shamir-Adleman aka RSA) encryption on tcp servers
basic golang net package (aka https://pkg.go.dev/net) wrapper implementing rsa encryption with signatures with connections


# Server side example
this simple example will accept the incoming connections and perform the public key exchange
```go
package main

import (
	"fmt"
	"tcpRsa"
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
	}
}
```

# Client side example
dial's the target server prompting a key exchange then disconnects from the target
```go
package main

import (
	"fmt"
	"tcpRsa"
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

	fmt.Printf("CONNECTED TO %s\r\n", Conn.Remote().RemoteAddr().String())
}
```
