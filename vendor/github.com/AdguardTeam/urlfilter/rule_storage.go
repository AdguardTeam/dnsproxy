package urlfilter

import (
	"fmt"
	"sync"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
)

// RuleStorage is an abstraction that combines several rule lists
// It can be scanned using RuleStorageScanner, and also it allows
// retrieving rules by its index
//
// The idea is to keep rules in a serialized format (even original format in the case of FileRuleList)
// and create them in a lazy manner only when we really need them. When the filtering engine is
// being initialized, we need to scan the rule lists once in order to fill up the lookup tables.
// We use rule indexes as a unique rule identifier instead of the rule itself.
// The rule is created (see RetrieveRule) only when there's a chance that it's needed.
//
// Rule index is an int64 value that actually consists of two int32 values:
// One is the rule list identifier, and the second is the index of the rule inside of that list.
type RuleStorage struct {
	// Lists is an array of rules lists which can be accessed
	// using this RuleStorage
	Lists []RuleList

	listsMap map[int]RuleList // map with rule lists. map key is the list ID.
	cache    map[int64]Rule   // cache with the rules which were retrieved.

	sync.Mutex
}

// NewRuleStorage creates a new instance of the RuleStorage
// and validates the list of rules specified
func NewRuleStorage(lists []RuleList) (*RuleStorage, error) {
	if lists == nil {
		lists = make([]RuleList, 0)
	}

	listsMap := make(map[int]RuleList)

	for _, list := range lists {
		if _, ok := listsMap[list.GetID()]; ok {
			return nil, fmt.Errorf("duplicate list ID: %d", list.GetID())
		}

		listsMap[list.GetID()] = list
	}

	return &RuleStorage{
		Lists:    lists,
		listsMap: listsMap,
		cache:    map[int64]Rule{},
	}, nil
}

// NewRuleStorageScanner creates a new instance of RuleStorageScanner.
// It can be used to read and parse all the storage contents.
func (s *RuleStorage) NewRuleStorageScanner() *RuleStorageScanner {
	var scanners []*RuleScanner
	for _, list := range s.Lists {
		scanner := list.NewScanner()
		scanners = append(scanners, scanner)
	}

	return &RuleStorageScanner{
		Scanners: scanners,
	}
}

// RetrieveRule looks for the filtering rule in this storage
// storageIdx is the lookup index that you can get from the rule storage scanner
func (s *RuleStorage) RetrieveRule(storageIdx int64) (Rule, error) {
	s.Lock()
	defer s.Unlock()

	rule, ok := s.cache[storageIdx]
	if ok {
		return rule, nil
	}

	listID, ruleIdx := storageIdxToRuleListIdx(storageIdx)

	list, ok := s.listsMap[int(listID)]
	if !ok {
		return nil, fmt.Errorf("list %d does not exist", listID)
	}

	f, err := list.RetrieveRule(int(ruleIdx))
	if f != nil {
		s.cache[storageIdx] = f
	}

	return f, err
}

// RetrieveNetworkRule is a helper method that retrieves a network rule from the storage
// It returns a pointer to the rule or nil in any other case (not found or error)
func (s *RuleStorage) RetrieveNetworkRule(idx int64) *NetworkRule {
	r, err := s.RetrieveRule(idx)
	if err != nil {
		log.Error("Cannot retrieve rule %d: %s", idx, err)
		return nil
	}

	v, ok := r.(*NetworkRule)
	if ok {
		return v
	}

	return nil
}

// RetrieveHostRule is a helper method that retrieves a host rule from the storage
// It returns a pointer to the rule or nil in any other case (not found or error)
func (s *RuleStorage) RetrieveHostRule(idx int64) *HostRule {
	r, err := s.RetrieveRule(idx)
	if err != nil {
		log.Error("Cannot retrieve rule %d: %s", idx, err)
		return nil
	}

	v, ok := r.(*HostRule)
	if ok {
		return v
	}

	return nil
}

// Close closes the storage instance
func (s *RuleStorage) Close() error {
	if len(s.Lists) == 0 {
		return nil
	}

	var errs []error

	for _, l := range s.Lists {
		err := l.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errorx.DecorateMany("couldn't close all rule lists", errs...)
	}

	return nil
}
