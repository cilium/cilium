package daemon

// Ping simply returns "Pong" when invoked.
func (d *Daemon) Ping() (string, error) {
	return "Pong", nil
}
