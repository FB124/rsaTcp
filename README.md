# rsaTcp - lightweight rsa implementaion of asymmetric (Rivest-Shamir-Adleman aka RSA) encryption on tcp servers
basic golang net package (aka https://pkg.go.dev/net) wrapper implementing rsa encryption with signatures with connections


# Server side example
this simple example will accept the incoming connections and perform the public key exchange
```go
package main

import (
	"fmt"
	"github.com/FB124/rsaTcp"
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

	fmt.Printf("CONNECTED TO %s\r\n", Conn.Remote().RemoteAddr().String())
}
```

# Custom key documentation
to implement the custom key functionality you may either use the 2 options below (server & client)
```go
//server side custom listener with specified key
func NewListenerWithKey(host string, key *rsa.PrivateKey) (*Listener, error)
```
```go
//client side custom dial with specified key
func DialTargetWithKey(host string, key *rsa.PrivateKey) (*Dial, error)
```

# Fingerprint documentation
support for gathering the public key's fingerprint information correctly
```go
//grabs the remote hosts fingerprint
func (c *Conn) RemoteFingerprint() ([]byte, error)
```
```go
//grabs the local fingerprint being used correctly
func (c *Conn) LocalFingerprint() ([]byte, error)
```

# Access more information inside the wrapper
this will allow you to access the socket (net.conn), private (*rsa.PrivateKey) & public (*rsa.PublicKey)
```go
//allows you to access the ongoing socket information
func (c *Conn) Remote() net.Conn
```
```go
//allows you to access the ongoing private key information
func (c *Conn) Private() *rsa.PrivateKey
```
```go
//allows you to access the ongoing public key information
func (c *Conn) Public() *rsa.PublicKey
```
# Coming soon!
* Exchange notes/messages
	- exchange custom information with the client/server when either dialing or accepting connections
