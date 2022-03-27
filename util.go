package rsaTcp

import (
	"crypto/rsa"
	"crypto/sha256"
)

//formats the rsa information to generate a fingerprint
//this will allow us to use for information like accessTokens and more
func (l *Listener) Fingerprint() ([]byte, error) {
	//creates a new hashblock
	//this will be used to correctly generate a fingerprint
	sB := sha256.New()
	//writes the public keys bytes to the sector
	//this will correctly write the N Curve bytes
	if _, err := sB.Write([]byte(l.Private.PublicKey.N.Bytes())); err != nil {
		//returns the error which was found correctly
		return nil, err
	}
	//returns the hashed block configuration
	//this will return the fingerprint properly
	return sB.Sum(nil), nil
}

func fingerprint(p *rsa.PublicKey) ([]byte, error) {
	//creates a new hashblock
	//this will be used to correctly generate a fingerprint
	sB := sha256.New()
	//writes the public keys bytes to the sector
	//this will correctly write the N Curve bytes
	if _, err := sB.Write([]byte(p.N.Bytes())); err != nil {
		//returns the error which was found correctly
		return nil, err
	}
	//returns the hashed block configuration
	//this will return the fingerprint properly
	return sB.Sum(nil), nil
}
