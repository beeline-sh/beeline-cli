package transport

import "testing"

func TestAuthLimiter(t *testing.T) {
	l := NewAuthLimiter()
	for i := 0; i < 9; i++ {
		if l.Fail("1.2.3.4:5000") {
			t.Fatalf("blocked after %d failures", i+1)
		}
	}
	if !l.Allow("1.2.3.4:6000") {
		t.Fatal("blocked too early")
	}
	if !l.Fail("1.2.3.4:5001") {
		t.Fatal("10th failure should block")
	}
	if l.Allow("1.2.3.4:7000") {
		t.Fatal("still allowed after block")
	}
	if !l.Allow("5.6.7.8:7000") {
		t.Fatal("other address affected")
	}
}
