package health

import "time"

type State string

const (
	Alive       State = "Alive"
	Degraded    State = "Degraded"
	Unreachable State = "Unreachable"
	Suspended   State = "Suspended"
)

func Evaluate(lastHeartbeat, now time.Time, suspended bool) State {
	if suspended {
		return Suspended
	}
	age := now.Sub(lastHeartbeat)
	if age <= 45*time.Second {
		return Alive
	}
	if age <= 180*time.Second {
		return Degraded
	}
	return Unreachable
}
