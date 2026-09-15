package portmap

import (
	"reflect"
	"testing"
)

func TestMerge(t *testing.T) {
	got := Merge([]string{"192.168.1.20:41820", "79.152.94.22:41820"}, "79.152.94.22:41820", "", "79.152.94.22:41821")
	want := []string{"192.168.1.20:41820", "79.152.94.22:41820", "79.152.94.22:41821"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := Merge(nil); len(got) != 0 {
		t.Fatalf("empty merge = %v", got)
	}
}
