package filterlist

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/AdguardTeam/urlfilter/rules"
)

// On Linux the size of the data block is usually 4KB
// So it makes sense to use 4KB.
const readerBufferSize = 4 * 1024

var (
	// ErrRuleRetrieval signals that the rule cannot be retrieved by RuleList
	// by the the specified index
	ErrRuleRetrieval = errors.New("cannot retrieve the rule")
)

// RuleList represents a set of filtering rules
type RuleList interface {
	GetID() int                                   // GetID returns the rule list identifier
	NewScanner() *RuleScanner                     // Creates a new scanner that reads the list contents
	RetrieveRule(ruleIdx int) (rules.Rule, error) // Retrieves a rule by its index
	io.Closer                                     // Closes the rules list
}

// StringRuleList represents a string-based rule list
type StringRuleList struct {
	ID             int    // Rule list ID
	RulesText      string // String with filtering rules (one per line)
	IgnoreCosmetic bool   // Whether to ignore cosmetic rules or not
}

// GetID returns the rule list identifier
func (l *StringRuleList) GetID() int {
	return l.ID
}

// NewScanner creates a new rules scanner that reads the list contents
func (l *StringRuleList) NewScanner() *RuleScanner {
	r := strings.NewReader(l.RulesText)

	return NewRuleScanner(r, l.ID, l.IgnoreCosmetic)
}

// RetrieveRule finds and deserializes rule by its index.
// If there's no rule by that index or rule is invalid, it will return an error.
func (l *StringRuleList) RetrieveRule(ruleIdx int) (rules.Rule, error) {
	if ruleIdx < 0 || ruleIdx >= len(l.RulesText) {
		return nil, ErrRuleRetrieval
	}

	endOfLine := strings.IndexByte(l.RulesText[ruleIdx:], '\n')
	if endOfLine == -1 {
		endOfLine = len(l.RulesText)
	} else {
		endOfLine += ruleIdx
	}

	line := strings.TrimSpace(l.RulesText[ruleIdx:endOfLine])
	if len(line) == 0 {
		return nil, ErrRuleRetrieval
	}

	return rules.NewRule(line, l.ID)
}

// Close does nothing as there's nothing to close in the StringRuleList
func (l *StringRuleList) Close() error {
	return nil
}

// FileRuleList represents a file-based rule list
type FileRuleList struct {
	ID             int      // Rule list ID
	IgnoreCosmetic bool     // Whether to ignore cosmetic rules or not
	File           *os.File // File with rules

	buffer []byte // buffer that is used for reading from the file
	sync.Mutex
}

// NewFileRuleList initializes a new file-based rule list
func NewFileRuleList(id int, path string, ignoreCosmetic bool) (*FileRuleList, error) {
	l := &FileRuleList{
		ID:             id,
		IgnoreCosmetic: ignoreCosmetic,
		buffer:         make([]byte, readerBufferSize),
	}

	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	l.File = f
	return l, nil
}

// GetID returns the rule list identifier
func (l *FileRuleList) GetID() int {
	return l.ID
}

// NewScanner creates a new rules scanner that reads the list contents
func (l *FileRuleList) NewScanner() *RuleScanner {
	_, _ = l.File.Seek(0, io.SeekStart)
	return NewRuleScanner(l.File, l.ID, l.IgnoreCosmetic)
}

// RetrieveRule finds and deserializes rule by its index.
// If there's no rule by that index or rule is invalid, it will return an error.
func (l *FileRuleList) RetrieveRule(ruleIdx int) (rules.Rule, error) {
	l.Lock()
	defer l.Unlock()

	if ruleIdx < 0 {
		return nil, ErrRuleRetrieval
	}

	_, err := l.File.Seek(int64(ruleIdx), io.SeekStart)
	if err != nil {
		return nil, err
	}

	// Read line from the file
	line, err := readLine(l.File, l.buffer)
	if err == io.EOF {
		err = nil
	}

	// Check if there were any errors while reading
	if err != nil {
		return nil, err
	}

	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return nil, ErrRuleRetrieval
	}

	return rules.NewRule(line, l.ID)
}

// Close closes the underlying file
func (l *FileRuleList) Close() error {
	return l.File.Close()
}

// readLine reads from the reader until '\n'
// r - reader to read from
// b - buffer to use (the idea is to reuse the same buffer when it's possible)
func readLine(r io.Reader, b []byte) (string, error) {
	line := ""

	for {
		n, err := r.Read(b)
		if n > 0 {
			idx := bytes.IndexByte(b[:n], '\n')
			if idx == -1 {
				line += string(b[:n])
			} else {
				line += string(b[:idx])
				return line, err
			}
		} else {
			return line, err
		}
	}
}
