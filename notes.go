package rtcp

//custom structure to allow information to be transferred easier
//this will allow the instance to tranfer custom notes/messages to either side
type Notes struct {
	//allows you to set a custom header into the information
	//this will allow the other side of the network to view the name
	header string
	//stores the value of the header information
	//allows the other side to view the value of the certain header
	value string
}

type Note []Notes

//starts a new method instance correctly
func New() Note {
	return Note(make([]Notes, 0))
}

//creates the new note class information
//this will store information about the notes safely and correctly
func (n *Note) NewNote(header string, value string) Note {
	//appends and returns the array information correctly
	return Note(append(*n, Notes{header:  header, value: value}))
}