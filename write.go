package rtcp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

//correctly writes to the remote host safely
//please note that the output will be larger than the incoming m field due to the signature & the encryption layers
func (c *Conn) Write(m []byte) (int, error) {

	//starts by placing the message into rsa encryption
	//makes sure the information is secured properly and safely
	MV, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.public, m, nil)

	//err handles the encrypt statement properly
	//this will allow us to error handle the encryption
	if err != nil {
		//returns the error correctly
		return 0, err
	}

	//signs the incoming message correctly
	//this will be transported in the marshal statement
	Signature, err := c.signMessage(MV)

	//err handles the sign information struct
	//makes sure we have correctly generated a signature
	if err != nil {
		//returns the error correctly
		return 0, err
	}

	//creates the message value holder
	//we will compress this using json safely
	var Msg Message = Message{
		//stores the message information encrypted & encoded
		Message: []byte(base64.RawStdEncoding.EncodeToString(MV)),
		//stores the signature encoded with std encoding
		Signature: []byte(base64.RawStdEncoding.EncodeToString(Signature)),
	}

	//completely converts the values into a string
	//this will allow us to correctly send the information
	Value, err := json.Marshal(&Msg)

	//err handles the marshal structure correctly
	//makes sure we can completely handle the error
	if err != nil {
		//returns the error correctly
		return 0, err
	}

	//encrypts the message correctly
	//this will be broadcasted across the network properly
	embed, err := c.layerEncrypt(Value)

	//err handles the encrypt statement properly
	//allows us to properly read the statement properly
	if err != nil {
		//returns the error correctly
		return 0, err
	}
	
	//stores the information correctly
	//this will allow better logging information
	c.Written += len(embed)

	//writes the encrypted message to the socket
	return c.socket.Write(embed)
}