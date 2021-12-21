package rtcp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

//reads the incoming input correctly and safely
//this will properly read the incoming message from the remote host
func (c *Conn) Reader(buffer int) ([]byte, error) { 
	//allows us to create a live buffer safely for the incoming messages
	//this will allow us to safely create a information truma 
	//please note the size allocated is including the expected json size ratio
	Buf := make([]byte, c.private.PublicKey.N.BitLen() + 20 + buffer)

	//reads the incoming traffic correctly
	//this will allow us to decrypt the incoming information properly
	_, err := c.socket.Read(Buf)

	//err handles the incoming statement correctly
	//allows us to correctly encrypt the information
	if err != nil {
		//returns the error correctly
		return nil, err
	}

	//completely decrypts the aes information around the text
	//makes sure we have correctly decodes the statement properly and safely
	Text, err := c.layerDecrypt(Buf)
	
	//err handles the decrypt statement
	//makes sure we have completely removed the aes information
	if err != nil {
		//returns the error correctly
		return nil, err
	}

	//creates a memory object which will store the information
	//this will make sure we have correctly create the memory for the object
	var incomingMessage Message

	//umarshals the data structure correctly
	//this will allow us to correctly insert information
	err = json.Unmarshal(Text, &incomingMessage)

	//err handles the umarshal statement
	//makes sure we have correctly stored the information
	if err != nil {
		//returns the error correctly
		return nil, err
	}

	//this will completely sort the information out properly and safely
	//makes sure we can completely access the information
	//we will encoding both options using rawSTD encoding properly and safely
	RawSignature, err := base64.RawStdEncoding.DecodeString(string(incomingMessage.Signature))

	//err handles the statement correctly and properly
	//makes sure we have access to the information properly
	if err != nil {
		//returns the errors correctly and safely
		return nil, err
	}

	//this will completely sort the information out properly and safely
	//makes sure we can completely access the information
	//we will encoding both options using rawSTD encoding properly and safely
	RawMessage, err := base64.RawStdEncoding.DecodeString(string(incomingMessage.Message))

	//err handles the statement correctly and properly
	//makes sure we have access to the information properly
	if err != nil {
		//returns the errors correctly and safely
		return nil, err
	}

	//tries to verify the messages source correctly
	//this will make sure we only accept messages from certain places
	if err := c.verifySignature(RawSignature, RawMessage); err != nil {
		//returns the error correctly
		return nil, err
	}

	//decrypts the incoming message correctly
	//this will output the information safely and correctly
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, c.private, RawMessage, nil)
}