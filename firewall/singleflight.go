package firewall

import "sync"

// flightGroup is a minimal local copy of golang.org/x/sync/singleflight (no dependency): calls
// to Do with the same key share one execution of fn while it runs.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flightCall
}

type flightCall struct {
	wg  sync.WaitGroup
	val any
	err error
}

// Do runs fn once for concurrent callers of the same key; every caller gets its result.
func (g *flightGroup) Do(key string, fn func() (any, error)) (any, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = map[string]*flightCall{}
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &flightCall{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		c.wg.Done()
	}()
	c.val, c.err = fn()
	return c.val, c.err
}
