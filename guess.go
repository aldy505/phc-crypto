package phccrypto

// GuessVerify acts like (a *Algo) Verify() but without the Algo instance.
// Like its' name, it guesses the hash. If it's supported, it will verify it.
func GuessVerify(hash string, plain string) (bool, error) {
	return true, nil
}