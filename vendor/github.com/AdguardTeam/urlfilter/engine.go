package urlfilter

// Engine represents the filtering engine with all the loaded rules
type Engine struct {
}

// NewEngine parses the filtering rules and creates a filtering engine of them
func NewEngine(rules string) (*Engine, error) {
	if rules == "" {
		// Empty engine
		return nil, nil
	}

	return &Engine{}, nil
}

// Match matches the specified request and looks for a matching filtering rule
func (e *Engine) Match(r *Request) (bool, Rule) {
	return false, nil
}
