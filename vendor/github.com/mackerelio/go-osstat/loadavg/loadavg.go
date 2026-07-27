package loadavg

// Get load average
func Get() (*Stats, error) {
	return get()
}

// Stats represents load average values
type Stats struct {
	Loadavg1, Loadavg5, Loadavg15 float64
}
