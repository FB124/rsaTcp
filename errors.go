package rsaTcp

import "errors"

var (
	//error code when the fingerprints pinged back don't match the fingerprints for the instance
	//makes sure that the instance is mostly valid and has access to the information
	ErrFingerprintContest error = errors.New("fingerprints passed can't be matched correctly")

	//error code when the json marshal statement in read didn't update anything
	ErrReadUmarshal error = errors.New("failed to completely parse the information safely")
)
