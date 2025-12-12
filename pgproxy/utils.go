package pgproxy

import (
	"strings"
	"sync"
)

// Counter provides a concurrent counter with semaphore protected access
type Counter struct {
	val  int
	lock sync.Mutex
}

func (c *Counter) Inc() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.val++
}

func (c *Counter) Dec() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.val--
}

func (c *Counter) Value() int {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.val
}

// trimEmptySyntax trims a given character set from the beginning and end of a
// string and repeats until no changes are detected anymore
func trimEmptySyntax(s string) string {
	lengthPrev := 0
	for {
		s = strings.Trim(s, " \n\t\r\f") // Remove all leading and trailing characters that do not have a meaning
		if len(s) == lengthPrev {
			return s
		}
		lengthPrev = len(s)
	}
}
