package rsaTcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
)

//correctly encrypts the data options for the m input
//completely encrypts the options which we want to encrypt
func (c *Conn) layerEncrypt(m []byte) ([]byte, error) {

	//we will force the use of the fingerprint for the encrypting key
	//this will make sure we use the remote fingerprint for the encrypting message
	fingerprint, err := fingerprint(c.public)

	//err handles the fingerprint statement correctly
	//makes sure we can grab the fingerprint correctly and safely
	if err != nil {
		//returns the error which was gotton
		return nil, err
	}

	//creates the new fingerprint cipher channel
	//this will be used for encrypting mainly and correctly
	cBlock, err := aes.NewCipher(fingerprint)

	//err handles the new cipher statement
	//makes sure we correctly generated the cipher
	if err != nil {
		//returns the information correctly
		return nil, err
	}

	//creates a new instance blockage
	//we will use this to store our information properly
	cText := make([]byte, aes.BlockSize + len(m))

	//creates the vector for the aes iv
	//allows us to properly encrypt using a CFB encryper
	iVector := cText[:aes.BlockSize]

	//returns the ivector correctly sorted properly
	//this will allow us to use it properly and safely
	if _, err := io.ReadFull(rand.Reader, iVector); err != nil {
		//returns the error which was gotton
		return nil, err
	}

	//creates the new cfb stream correctly
	//this entire section will also return the encoded stream byte
	stream := cipher.NewCFBEncrypter(cBlock, iVector)
	stream.XORKeyStream(cText[aes.BlockSize:], m)
	return []byte(base64.RawStdEncoding.EncodeToString(cText)), nil
} 

//correctly decrypts the incoming information
//we will use our section information to decrypt this part
func (c *Conn) layerDecrypt(m []byte) ([]byte, error) {

	//completely removes all security of the text which is currently active
	//this will output the raw exchange values properly and safely for our read/other input functions
	cText, err := base64.RawStdEncoding.DecodeString(strings.ReplaceAll(string(m), "\x00", ""))

	//err handles the decode statement
	//this will output the byte values correctly
	if err != nil {
		//returns the error correctly
		return nil, err
	}

	//correctly uses our private public key for the fingerprint
	//this will allow us to decrypt the information if the remote host is valid
	Fingerprint, err := fingerprint(&c.private.PublicKey)
	
	//err handles the fingerprint statement
	//makes sure we have access to the fingerprint
	if err != nil {
		//returns the error information correctly
		return nil, err
	}

	//err handles the fingerprint statement
	//makes sure we have access to the key/information
	block, err := aes.NewCipher(Fingerprint)

	//err handles the new cipher statement
	//makes sure we have access to the block information
	if err != nil {
		//returns the errors correctly and properly
		return nil, err
	}

	//sorts the information correctly and safely out
	//mainly used for our encrypting statement safely
	installedVector, cText := cText[:aes.BlockSize], cText[aes.BlockSize:]

	//creates a new cfb decryptor instance
	//this will decrypt the text correctly and properly
	stream := cipher.NewCFBDecrypter(block, installedVector)
	stream.XORKeyStream(cText, cText)
	//returns the raw output from the function
	return cText, nil
}
