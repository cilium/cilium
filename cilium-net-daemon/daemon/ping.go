package daemon

func (d Daemon) Ping() (string, error) {
	return "Pong", nil
}
