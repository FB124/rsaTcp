package rtcp 



//this will allow the information to be correctly stored inside safely
//allows information which is being passed to be validated using the signature
type Message struct {
	//stores the message which is being sent via the server
	//allows us to send anything via each node safely & correctly
	Message []byte //this will store the content we are broadcasting across the node

	//stores how we will validate the information
	//makes sure we can correctly validate the information
	Signature []byte

}