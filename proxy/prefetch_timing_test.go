package proxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPrefetch_TimingLogic(t *testing.T) {
	// Helper to create a dummy manager with specific config
	newManager := func(refreshBefore time.Duration) *PrefetchQueueManager {
		return &PrefetchQueueManager{
			refreshing:    make(map[string]bool),
			refreshBefore: refreshBefore,
		}
	}

	tests := []struct {
		name          string
		refreshBefore time.Duration
		ttl           time.Duration
		expected      time.Duration
	}{
		{
			name:          "Long TTL, Small RefreshBefore",
			refreshBefore: 5 * time.Second,
			ttl:           300 * time.Second,
			expected:      30 * time.Second, // 10% of 300s = 30s. max(30, 5) = 30s.
		},
		{
			name:          "Long TTL, Large RefreshBefore",
			refreshBefore: 60 * time.Second,
			ttl:           300 * time.Second,
			expected:      60 * time.Second, // 10% of 300s = 30s. max(30, 60) = 60s.
		},
		{
			name:          "Medium TTL",
			refreshBefore: 5 * time.Second,
			ttl:           60 * time.Second,
			expected:      6 * time.Second, // 10% of 60s = 6s. max(6, 5) = 6s.
		},
		{
			name:          "Short TTL",
			refreshBefore: 5 * time.Second,
			ttl:           10 * time.Second,
			expected:      5 * time.Second, // 10% of 10s = 1s. max(1, 5) = 5s. Cap(5) -> 5s.
		},
		{
			name:          "Very Short TTL",
			refreshBefore: 5 * time.Second,
			ttl:           2 * time.Second,
			expected:      1 * time.Second, // 10% of 2s = 0.2s. max(0.2, 5) = 5s. Cap(1) -> 1s.
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := newManager(tc.refreshBefore)
			item := &PrefetchItem{
				AddedTime:  time.Now(),
				ExpireTime: time.Now().Add(tc.ttl),
			}

			actual := pm.calculateEffectiveRefreshBefore(item)
			assert.Equal(t, tc.expected, actual, "Failed for TTL %v, RefreshBefore %v", tc.ttl, tc.refreshBefore)
		})
	}
}
