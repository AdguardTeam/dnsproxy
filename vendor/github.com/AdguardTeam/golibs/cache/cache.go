package cache

// Config - configuration
type Config struct {
	// Max. cache size (in bytes) of keys and values.  Default: unlimited
	MaxSize uint

	// Max. element size (in bytes).  Default: =MaxSize
	MaxElementSize uint

	// Max. elements number.  Default: unlimited
	MaxCount uint

	// When cache is full, the least recently used element is deleted automatically
	EnableLRU bool

	// User callback function which is called after an element has been deleted automatically
	OnDelete onDeleteType
}

// New - create cache object
func New(conf Config) Cache {
	return newCache(conf)
}

// Cache - interface
type Cache interface {
	// Set data
	// Return FALSE if data was added;  TRUE if data was replaced
	Set(key []byte, val []byte) bool

	// Get data
	// Return nil if item with this key doesn't exist
	Get(key []byte) []byte

	// Delete data
	Del(key []byte)

	// Clear all data and statistics
	Clear()

	// Get statistics data
	Stats() Stats
}

// Stats - counters
type Stats struct {
	Count int
	Size  int
	Hit   int
	Miss  int
}
