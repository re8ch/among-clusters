package health

import (
	"testing"
	"time"
)

func TestEvaluate(t *testing.T) {
	now := time.Now()
	cases := []struct {
		age       time.Duration
		suspended bool
		want      State
	}{{10 * time.Second, false, Alive}, {60 * time.Second, false, Degraded}, {181 * time.Second, false, Unreachable}, {0, true, Suspended}}
	for _, c := range cases {
		if got := Evaluate(now.Add(-c.age), now, c.suspended); got != c.want {
			t.Fatalf("age=%v got %s want %s", c.age, got, c.want)
		}
	}
}
