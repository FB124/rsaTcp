package rtcp

import (
	"crypto/rsa"
	"net"
)

//stores information about ongoing connections correctly
//this will allow either server & client side structures to handle information
type Conn struct {
	//stores the socket information
	//this will allow us to handle information for the conn
	socket net.Conn
	//stores the connections public key correctly
	//this is what is used for encrypting the messages correctly
	public *rsa.PublicKey
	//stores the systems private key
	//this will be used to decrypt messages correctly
	private  *rsa.PrivateKey
	//stores all the bytes we have written to the remote host safely
	//this will allow us to correctly handle this information properly
	Written int
	//exchange notes, this will allow you to forward custom information with the system
	//custom messages with headers and values built inside a payload
}

//syncs the dial client with the conn struct
//allows us to access conn structure information
func (d *Dial) MakeConn() *Conn {
	return &Conn{
		//stores the ongoing socket interface
		//allows us to write information towards it
		socket: d.socket,
		//stores the public key for encryption
		//this will be used for encrypting messages towards the header
		public: d.public,
		//stores our private key correctly
		//this will allow us to corrctly decrypt incoming messages
		private: d.private,
		//allows us to track how much we have written to the remote host
		//this allows an enhanced logging experience which can induce better logging
		Written: 0,
	}
}

//syncs the listener and client with the conn struct
//allows us to access conn structure information correctly
func (c *Client) MakeConn() *Conn {
	return &Conn{
		//stores the ongoing socket interface
		//allows us to write information towards it
		socket: c.conn,
		//stores the public key for encryption
		//this will be used for encrypting messages towards the header
		public: c.public,
		//stores our private key correctly
		//this will allow us to corrctly decrypt incoming messages
		private: c.private,
	}
}

//allows the information to access the public method
//gives us more information about the client properly
func (c *Conn) Remote() net.Conn {
	return c.socket
}