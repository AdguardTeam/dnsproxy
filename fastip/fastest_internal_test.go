package fastip

// SetPingPorts is a method that allows setting the private pingPorts field
// for FastestAddr, used for external tests.
func (f *FastestAddr) SetPingPorts(ports []uint) {
	f.pingPorts = ports
}
