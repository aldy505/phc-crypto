package phccrypto_test

import (
	"reflect"
	"testing"

	phccrypto "github.com/aldy505/phc-crypto"
)

func TestRandom(t *testing.T) {
	random := phccrypto.Random()
	typeof := reflect.TypeOf(random).Kind()
	if typeof != reflect.Int {
		t.Error("expected int, found:", typeof)
	}
}