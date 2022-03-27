package rsaTcp

import (
	"crypto/rsa"
	"net"
)

//stores information about the client
//this will give us more information about the client
type Client struct {
	//stores the clients interface
	//this will allow us to message/read to/from client
	conn net.Conn
	//stores the clients public key
	//we can write to the client using that information
	public *rsa.PublicKey
	//stores the private key information
	//we can decrypt information coming from the client
	private *rsa.PrivateKey
}


//accepts the new incoming connection
//this will accept and perform the rsa exchange properly
func (l *Listener) AcceptConnection() (*Client, error) {

	//accepts the incoming connection properly
	//this will allow us to interface with the connection
	conn, err := l.listener.Accept()

	//err handles the accept protocol
	//makes sure the client was accepted properly
	if err != nil {
		//returns the err
		return nil, err
	}

	//performs the valid pingexchange system
	//this will forceful exchange the information properly
	return l.PingExchangeServer(conn)
}
