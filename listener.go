package rsaTcp

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
)

//allows control over certain information
//this will allow us to control our information about the listener
type Listener struct {
	//stores the host which we will listen on
	//this option is the interface which the listener will attach & listen to
	Host string

	//stores the private key which we will listen to properly
	//this will allow us to properly create a new listener safely & properly
	Private *rsa.PrivateKey

	//stores the listener configuration
	//this will allow us to edit this at any point
	listener net.Listener
}


//creates a new listener with a randomly generated rsa key
//this will properly listen to the host on the port selected
func NewListener(host string) (*Listener, error) {
	//creates a new random rsa key
	//this will be used during the encryption proc
	Generated, err := rsa.GenerateKey(rand.Reader, 2048)

	//err handles the creation statement
	//this will allow us to properly error handle the creation
	if err != nil {
		//returns the error which was given properly
		return nil, err
	}
	

	//creates a listener struct properly
	//we will use this to access other structures using a method
	var Lst *Listener = &Listener{
		//stores the host/target which we will listen on
		//interface for the listener to attach to properly
		Host: host,
		//stores the private key which will be used for encryption
		//this ca either be randomly generated or passed in
		Private: Generated,
	}

	//creates a listener and returns any errors
	//makes sure that when the listener is created no errors have been recorded 
	return Lst.createListener()
}


//creates a listener with a key chosen
//this allows the instance to chose the port it listens to
func NewListenerWithKey(host string, key *rsa.PrivateKey) (*Listener, error) {

	//creates a listener struct properly
	//this will allow us to access more methods
	var Lst *Listener = &Listener{
		//stores the host/target which we will listen on
		//interface for the listener to attach to properly
		Host: host,
		//stores the private key which will be used for encryption
		//this ca either be randomly generated or passed in
		Private: key,
	}

	//creates a listener and returns any errors
	//makes sure that when the listener is created no errors have been recorded 
	return Lst.createListener()
}


//creates the listener using the configuration given
//this will correctly create a new listener properly and safely
func (l *Listener) createListener() (*Listener, error) {
	//creates a new listener on the port given
	//this will broadcast the listener to that port properly
	listen, err := net.Listen("tcp", l.Host)

	//stores the listener configuration
	//this will allow us to access the information easily
	l.listener = listen

	//returns the information given from the function
	//makes sure the main function has access to the information
	return l, err
}
