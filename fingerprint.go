package rsaTcp 



//returns the remote hosts valid fingerprint information
//this can be used for authentication purposes or more information
func (c *Conn) RemoteFingerprint() ([]byte, error) {
	//returns the remote hosts fingerprint information correctly
	return fingerprint(c.public)
}

//returns the local hosts valid fingerprint information
//this can be used for authentication purposes or more information
func (c *Conn) LocalFingerprint() ([]byte, error) {
	//returns the local hosts fingerprint information correctly
	return fingerprint(&c.private.PublicKey)
}
