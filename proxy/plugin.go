package proxy

import (
	"github.com/joomcode/errorx"
	log "github.com/sirupsen/logrus"
)

// PluginResponse represents possible response statuses
// Values of this type are returned from BeforeRequest() or AfterResponse()
type PluginResponse uint16

const (
	// Processed is the default value for PluginResponse.
	// The next plugin in chain must be called (unless there was an error)
	Processed PluginResponse = iota
	// ReturnImmediately means that next plugins must be ignored and we must return response (or no response) to the client
	ReturnImmediately
	// ReturnNoResponse means that next plugins must be ignored,
	// and that we must send no response to the client (and close connection)
	ReturnNoResponse
)

// Plugin is a general interface for extending DNS proxy functionality
type Plugin interface {
	// Name returns plugin name (for logging mostly)
	Name() string
	// BeforeRequest is called before the specified request is passed to the upstream
	BeforeRequest(d *DnsContext) (PluginResponse, error)
	// AfterRequest is called after the response was already received from the upstream
	AfterResponse(d *DnsContext) (PluginResponse, error)
}

// beforeRequest applies plugins BeforeRequest function one-by-one
func (p *Proxy) beforeRequest(d *DnsContext) (PluginResponse, error) {
	if len(p.Plugins) == 0 {
		return Processed, nil
	}

	for _, plugin := range p.Plugins {
		log.Debugf("%s.BeforeRequest", plugin.Name())
		r, err := plugin.BeforeRequest(d)

		if err != nil {
			return Processed, errorx.Decorate(err, "error in %s.BeforeRequest", plugin.Name())
		}

		if r == Processed {
			continue
		} else {
			return r, nil
		}
	}

	return Processed, nil
}

// afterRequest applies plugins BeforeRequest function one-by-one
func (p *Proxy) afterRequest(d *DnsContext) (PluginResponse, error) {
	if len(p.Plugins) == 0 {
		return Processed, nil
	}

	for _, plugin := range p.Plugins {
		log.Debugf("%s.AfterRequest", plugin.Name())
		r, err := plugin.AfterResponse(d)

		if err != nil {
			return Processed, errorx.Decorate(err, "error in %s.AfterRequest", plugin.Name())
		}

		if r == Processed {
			continue
		} else {
			return r, nil
		}
	}

	return Processed, nil
}
