package rsaTcp

import (
	"errors"
	"net"
	"strings"
	"time"
)

//we will write the exchange system on a base
//base information
//	- the client forwards there public key towards the server
//	- we will authenticate the key and let the client know/be aware of this by pinging the fingerprint from the clients public key
//	- the server will then forward its public key towards the client
//	- and the client will authenticate it and ping to model back towards the server
func (l *Listener) PingExchangeServer(c net.Conn) (*Client, error) {
	//sets a read deadline for the information properly
	//makes sure we aren't forever waiting for the clients respone
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))


	//creates a buffer which we can read into properly
	//makes sure we are counting the information being written to the server
	cPublic := make([]byte, 5064)

	//reads the incoming information from the client properly
	//makes sure the incoming message is valid from the clients information
	_, err := c.Read(cPublic)

	//err handles the read statement properly
	//makes sure we have correctly read the incoming information
	if err != nil {
		//returns the err if one happened
		return nil, err
	}

	//gets the clients public key from the information given
	//makes sure the client knows that there accept has been valid
	cSPublic, err := accessPublicKey(string(cPublic))

	//err handles the statement correctly
	//makes sure the system knows about the error
	if err != nil {
		//trys to correctly close the connection with the remote host
		//makes sure we don't leave any invalid conns opens
		if err := c.Close(); err != nil {
			//returns the error from trying to close the conn
			return nil, err
		}

		return nil, err
	}

	//gets the clients fingerprint correctly
	//makes sure the client knows that there information has been accepted
	Fingerprint, err := fingerprint(cSPublic)

	//err handles the statement correctly
	//makes sure the system knows about the error
	if err != nil {
		//trys to correctly close the connection with the remote host
		//makes sure we don't leave any invalid conns opens
		if err := c.Close(); err != nil {
			//returns the error from trying to close the conn
			return nil, err
		}

		return nil, err
	}

	//pings the client with there fingerprint correctly
	//makes sure the clients knows that there key has been accepted properly
	if _, err := c.Write(Fingerprint); err != nil {
		//trys to correctly close the connection with the remote host
		//makes sure we don't leave any invalid conns opens
		if err := c.Close(); err != nil {
			//returns the error from trying to close the conn
			return nil, err
		}

		return nil, err
	}


	//this will correctly compress the servers key for the client
	//allows the client information to tell the server properly
	Server, err := publicKeyString(&l.Private.PublicKey)

	//err handles the statement above
	//makes sure the system knows that the key is invalid
	if err != nil {
		//trys to correctly close the connection with the remote host
		//makes sure we don't leave any invalid conns opens
		if err := c.Close(); err != nil {
			//returns the error from trying to close the conn
			return nil, err
		}

		return nil, err
	}

	//writes the public key to the remote client properly
	//makes sure the client can access the information properly
	if _, err := c.Write([]byte(Server)); err != nil {
		//trys to correctly close the connection with the remote host
		//makes sure we don't leave any invalid conns opens
		if err := c.Close(); err != nil {
			//returns the error from trying to close the conn
			return nil, err
		}

		return nil, err
	}

	//reads the bounce back from the statement
	//makes sure the client has correctly got the public key fingerprint
	cFingerprint := make([]byte, 1024)

	//reads the incoming information from the client properly
	//makes sure the incoming message is valid from the clients information
	_, err = c.Read(cFingerprint)

	//err handles the read statement properly
	//makes sure we have correctly read the incoming information
	if err != nil {
		//returns the err if one happened
		return nil, err
	}

	//gets the current listeners fingerprint properly
	//this will allow us to compare the fingerprints safelyt
	MyFingerprint, err := l.Fingerprint()

	//err handles the fingerprint statement correctly
	//makes sure no errors get any futher than this
	if err != nil {
		//trys to correctly close the connection with the remote host
		//makes sure we don't leave any invalid conns opens
		if err := c.Close(); err != nil {
			//returns the error from trying to close the conn
			return nil, err
		}

		return nil, err
	}


	//compares the 2 fingerprints
	//makes sure the client has created the same fingerprint
	if !strings.EqualFold(strings.ReplaceAll(string(cFingerprint), "\x00", ""), string(MyFingerprint)) {
		//returns the error for invalid fingerprint
		return nil, ErrFingerprintContest
	}

	//returns the information from the function correctly
	return &Client{conn: c, public: cSPublic, private: l.Private}, nil
}

//the client side information for the ping exchange
//makes sure we have correctly exchanged the information safely & correctly
func (d *Dial) PingExchangeClient() (*Dial, error) {

	//compress our key into a string which can be sent/written
	//makes sure the client/server can access our key when decoded safely
	KeyString, err := publicKeyString(&d.private.PublicKey)

	//err handles the compression string safely
	//makes sure no errors happened when trying to compress the key
	if err != nil {
		//makes sure we close the socket
		//prevents ongoing null socket connections
		if err := d.socket.Close(); err != nil {
			//returns the error which happened when trying to close the socket
			return nil, err
		}
		//returns the information error
		return nil, err
	}

	//writes our key to the remote host
	//makes sure we have correctly handled the information
	if _, err := d.socket.Write([]byte(KeyString)); err != nil {
		//returns the error which happened correctly
		return nil, err
	}

	//creates a live buffer
	//this will allow us to write into the buffer and access it futher on
	BufPublicAuth := make([]byte, 1024)

	//reads the incoming information from the remote host
	//makes sure we have correctly written into the buffer copied from the remote host
	_, err = d.socket.Read(BufPublicAuth)

	//err handles the read statement
	//makes sure we have correctly written into the buffer
	if err != nil {
		//returns the error which was given
		return nil, err
	}

	//creates the fingerprint for the clients information
	//this will allow us to create information for the client structure
	Fingerprint, err := fingerprint(&d.private.PublicKey)

	//err handles the fingerprint statement
	//makes sure we have a valid fingerprint created
	if err != nil {
		//makes sure we close the socket
		//prevents ongoing null socket connections
		if err := d.socket.Close(); err != nil {
			//returns the error which happened when trying to close the socket
			return nil, err
		}
		//returns the information error
		return nil, err
	}

	//compares the fingerprint safely
	//makes sure the key sent matches the one we have access to
	if !strings.EqualFold(strings.ReplaceAll(string(BufPublicAuth), "\x00", ""), string(Fingerprint)) {
		//returns the error for when the fingerprints don't match correctly
		return nil, ErrFingerprintContest
	}

	//creates a live buffer
	//this will allow us to write into the buffer and access it futher on
	BufPublicServer := make([]byte, 5064)

	//reads the incoming information from the remote host
	//makes sure we have correctly written into the buffer copied from the remote host
	_, err = d.socket.Read(BufPublicServer)

	//err handles the read statement
	//makes sure we have correctly written into the buffer
	if err != nil {
		//returns the error which was given
		return nil, err
	}


	//correctly error handles the information
	//this will access the public key from the []byte -> string information
	Public, err := accessPublicKey(string(BufPublicServer))

	//err handles the access public key string
	//makes sure we have the information we needed
	if Public == nil || err != nil {
		//makes sure we close the socket
		//prevents ongoing null socket connections
		if err := d.socket.Close(); err != nil {
			//returns the error which happened when trying to close the socket
			return nil, err
		}

		//makes sure the public key is equal to a nil pointer
		//allows us to enforce that the public key must not be nil
		if err != nil {
			//returns the error which was given correctly
			return nil, err
		}

		//returns the error which we got correctly
		return nil, errors.New("public decompressed is equal to nil pointer")
	}
	
	//gets the remote hosts fingerprint correctly
	//we will echo this system back to the remote host
	FingerprintServer, err := fingerprint(Public)

	//err handles the fingerprint statement properly
	//this will make sure the values are handled properly
	if err != nil {
		//returns the error correctly and safely
		return nil, err
	}
	
	//echos the fingerprint back correctly
	//makes sure we have correctly access the information
	if _, err := d.socket.Write(FingerprintServer); err != nil {
		//returns the error which we found correctly
		return nil, err
	}

	//correctly stores our information correctly
	d.public = Public

	return d, nil
}
