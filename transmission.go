package rsaTcp

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
)

//encodes the key properly
//this will return a string value supporting the listeners public key
//allows the client to properly access the servers main key safely and properly
func publicKeyString(public *rsa.PublicKey) (string, error) {

	//correctly marshals the structure into string format
	//this will allow us to compress/encode and return information
	Interface, err := json.Marshal(public)

	//err handles the json statement correctly
	//this will allow us to gain more information from the client
	if err != nil {
		//returns the information correctly
		return "", err
	}

	//returns the interface encoded with std encoding properly
	return base64.RawStdEncoding.EncodeToString(Interface), nil
}

//decodes the key from the string
//this will allow us to access the clients public key properly and safely
//means we can write to the client using their key properly and safely
func accessPublicKey(str string) (*rsa.PublicKey, error) {

	//decodes the string properly
	//allows us to access the raw information from the string
	Raw, err := base64.RawStdEncoding.DecodeString(strings.ReplaceAll(str, "\x00", ""))

	//err handles the decoding statement
	//means we will know if there was an error
	if err != nil {
		//handles the error which could of happened
		return nil, err
	}

	//temporary memory object which will store information
	//this will store the structure once umarhaled
	var ObjectTence rsa.PublicKey

	//unmarshales the information back into main information
	//this will convert the string back into the publickey structure
	err = json.Unmarshal(Raw, &ObjectTence)

	//err handles the umarhsal structure properly
	//this will make sure no errors happened 
	if err != nil {
		return nil, err
	}

	//returns the information properly and safely
	return &ObjectTence, nil
}
