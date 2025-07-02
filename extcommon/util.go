package extcommon

import (
	"log"
	"os/user"
	"regexp"

	"github.com/gobwas/glob"
	lru "github.com/hashicorp/golang-lru/v2"
)

const lruSize = 128

type cacheKey struct {
	pattern    string
	separators string
}

func newCacheKey(pattern string, separators []rune) cacheKey {
	var s string
	for _, c := range separators {
		s += string(c)
	}
	return cacheKey{pattern, s}
}

var globCache *lru.Cache[cacheKey, glob.Glob]
var regexpCache *lru.Cache[string, *regexp.Regexp]

// CompileGlob compiles a glob, using the LRU cache to retrieve a previously compiled pattern if
// possible.
func CompileGlob(pattern string, separators ...rune) (glob.Glob, error) {
	k := newCacheKey(pattern, separators)

	if g, ok := globCache.Get(k); ok {
		return g, nil
	}

	g, err := glob.Compile(pattern, separators...)
	if err != nil {
		return nil, err
	}
	globCache.Add(k, g)
	return g, nil
}

// CompileRegexp compiles a regexp, using the LRU cache to retrieve a previously compiled pattern if
// possible.
func CompileRegexp(pattern string) (*regexp.Regexp, error) {
	if r, ok := regexpCache.Get(pattern); ok {
		return r, nil
	}

	r, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexpCache.Add(pattern, r)
	return r, nil
}

// ListUsers lists local user accounts.
func ListUsers() ([]*user.User, error) {
	return nil, nil
}

func init() {
	var err error

	globCache, err = lru.New[cacheKey, glob.Glob](lruSize)
	if err != nil {
		log.Fatal(err)
	}

	regexpCache, err = lru.New[string, *regexp.Regexp](lruSize)
	if err != nil {
		log.Fatal(err)
	}
}
