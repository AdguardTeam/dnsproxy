package mobile

import (
	"encoding/json"
	"strings"

	"github.com/joomcode/errorx"
)

// filtersListJSON represents filters list with list id
type filtersListJSON struct {
	ListID         int    `json:"id"`
	FilteringRules string `json:"contents"`
}

// decodeFilteringRulesMap decodes filtersJSON and returns filters map
func decodeFilteringRulesMap(filtersJSON string) (map[int]string, error) {
	var filters []filtersListJSON
	err := json.NewDecoder(strings.NewReader(filtersJSON)).Decode(&filters)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to decode filters json")
	}

	filtersMap := map[int]string{}
	for _, filter := range filters {
		filtersMap[filter.ListID] = filter.FilteringRules
	}

	return filtersMap, err
}
