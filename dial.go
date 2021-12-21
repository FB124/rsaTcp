package rtcp

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
)

//support for the rtcp server side instance
//this will provide support for the rtcp server side
type Dial struct {
	//stores the target which you would like to dial
	//this will be dialed and connected to properly
	host string
	//stores the client side private key you wish to dial using
	//this will be what we decrypt & send the server side to encrypt messages
	private *rsa.PrivateKey
	//stores the socket information
	//this will allow us to write & exchange more information with the target
	socket net.Conn
	//stores the socket public key
	//this will help us perform the exchange correctly & safely
	public *rsa.PublicKey
}


//dials the target with the host and randomly generated rsa key
//this will allow us to connect to the target correctly and safely
func DialTarget(host string) (*Dial, error) {
	//creates a new rsa random key
	//this will be used for decryption & encryption from the server
	Generated, err := rsa.GenerateKey(rand.Reader, 2048)

	//err handles the generate statement
	//makes sure the instance knows that there was an error
	if err != nil {
		//returns the error to the host instance
		return nil, err
	}

	//creates a new dial client instance
	//this will be mainly used as the method for the dial client
	var Dil *Dial = &Dial{
		//stores the host/target which we will dial towards
		//this will interface with the dial client to dial towards the target
		host: host,
		//stores the private key safely
		//this will be used to decrypt incoming messages
		private: Generated,
	}

	
	//dials towards the target using the tcp protocol
	//this will make sure we have connected with the server
	Dil, err = Dil.createConnection()

	//err handles the dial statement correctly
	//makes sure we have connected with the target
	if err != nil {
		//returns the error which was found correctly
		return nil, err
	}

	//performs the ping exchange with the server
	//exchanges the information correctly and safely
	return Dil.PingExchangeClient()
}

//dials the target with the host and rsa key passed into the function
//this will allow us to connect to the target correctly and safely
func DialTargetWithKey(host string, key *rsa.PrivateKey) (*Dial, error) {

	//creates a new dial client instance
	//this will be mainly used as the method for the dial client
	var Dil *Dial = &Dial{
		//stores the host/target which we will dial towards
		//this will interface with the dial client to dial towards the target
		host: host,
		//stores the private key safely
		//this will be used to decrypt incoming messages
		private: key,
	}

	
	//dials towards the target using the tcp protocol
	//this will make sure we have connected with the server
	Dil, err := Dil.createConnection()

	//err handles the dial statement correctly
	//makes sure we have connected with the target
	if err != nil {
		//returns the error which was found correctly
		return nil, err
	}

	//performs the ping exchange with the server
	//exchanges the information correctly and safely
	return Dil.PingExchangeClient()
}

func (d *Dial) createConnection() (*Dial, error) {
	//creates the new dial client properly
	//we can dial safely with this information
	dial, err := net.Dial("tcp", d.host)
	//saves the dial information into the struct
	//makes sure we can access this information properly
	d.socket = dial
	//returns the information which we was given
	//allows us to access the information more concurrently
	return d, err
}
