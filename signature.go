package rsaTcp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

//allows us to correctly verify the message details
//this will make sure he can access the information safely
func (c *Conn) verifySignature(signature, message []byte) error {
	//we will hash the message futher to create the env properly
	//this will provide another layer of security ontop of the signature
	Layer := sha256.New()
	//writes the texture information to the block
	//makes sure we can correctly hash the incoming message
	if _, err := Layer.Write(message); err != nil {
		return err
	}
	//returns the output from the verify message seq
	//makes sure we can verify the source of the message
	return rsa.VerifyPKCS1v15(c.public, crypto.SHA256, Layer.Sum(nil), signature)
}

//signs the message correctly and safely
//means we can verify the messages source correctly on the direct other end
func (c *Conn) signMessage(message []byte) ([]byte, error) {
	//we will hash the message futher to create the env properly
	//this will provide another layer of security ontop of the signature
	Layer := sha256.New()
	//writes the texture information to the block
	//makes sure we can correctly hash the incoming message
	if _, err := Layer.Write(message); err != nil {
		return nil, err
	}
	//returns the signature correctly and safely
	//this will allow us to verify the source correctly
	return rsa.SignPKCS1v15(rand.Reader, c.private, crypto.SHA256, Layer.Sum(nil))
}
