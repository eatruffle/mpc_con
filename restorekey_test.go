package restorekey

import "testing"

func RestoreKeyTest(t *testing.T) {

	key := RestoreKey()

	if key != "" {
		t.Errorf("Wrong key")
	}

}
