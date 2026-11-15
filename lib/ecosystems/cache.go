/*
 * © 2023 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ecosystems

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/package-url/packageurl-go"
	"golang.org/x/sync/singleflight"

	"github.com/snyk/parlay/ecosystems/packages"
)

const (
	// defaultMaxCacheEntries bounds each positive (2xx) response cache.
	defaultMaxCacheEntries = 10000
	// defaultMaxNegativeCacheEntries bounds each negative (404) cache.
	defaultMaxNegativeCacheEntries = 1000
)

type Cache interface {
	GetPackageData(purl packageurl.PackageURL) (*packages.GetRegistryPackageResponse, error)
	GetPackageVersionData(purl packageurl.PackageURL) (*packages.GetRegistryPackageVersionResponse, error)
}

type InMemoryCache struct {
	packageCache           map[string]*packages.GetRegistryPackageResponse
	packageVersionCache    map[string]*packages.GetRegistryPackageVersionResponse
	packageNotFound        map[string]struct{}
	packageVersionNotFound map[string]struct{}
	maxEntries             int
	maxNegativeEntries     int
	mu                     sync.RWMutex
	packageGroup           singleflight.Group
	packageVersionGroup    singleflight.Group
}

var (
	globalCache     *InMemoryCache
	globalCacheOnce sync.Once
)

func NewInMemoryCache() *InMemoryCache {
	return &InMemoryCache{
		packageCache:           make(map[string]*packages.GetRegistryPackageResponse),
		packageVersionCache:    make(map[string]*packages.GetRegistryPackageVersionResponse),
		packageNotFound:        make(map[string]struct{}),
		packageVersionNotFound: make(map[string]struct{}),
		maxEntries:             defaultMaxCacheEntries,
		maxNegativeEntries:     defaultMaxNegativeCacheEntries,
	}
}

// GetGlobalCache returns a singleton cache instance that persists for the lifetime of the process.
// This cache is shared across all SBOM enrichments to avoid repeated API calls for the same packages,
// including 404 responses for non-existent packages. Only successful (2xx) responses are cached
// positively; 404 responses are held in a bounded negative cache, and 5xx responses are surfaced
// as errors and never cached.
func GetGlobalCache() *InMemoryCache {
	globalCacheOnce.Do(func() {
		globalCache = NewInMemoryCache()
	})
	return globalCache
}

// ResetGlobalCache resets the global cache. This is primarily for testing purposes.
func ResetGlobalCache() {
	globalCache = nil
	globalCacheOnce = sync.Once{}
}

func (c *InMemoryCache) GetPackageData(purl packageurl.PackageURL) (*packages.GetRegistryPackageResponse, error) {
	key := purl.ToString()

	c.mu.RLock()
	if cached, exists := c.packageCache[key]; exists {
		c.mu.RUnlock()
		return cached, nil
	}
	_, notFound := c.packageNotFound[key]
	c.mu.RUnlock()
	if notFound {
		return notFoundPackageResponse(), nil
	}

	result, err, _ := c.packageGroup.Do(key, func() (interface{}, error) {
		response, err := GetPackageData(purl)
		if err != nil {
			return nil, err
		}

		switch status := response.StatusCode(); {
		case status >= 200 && status < 300:
			c.mu.Lock()
			evictIfFull(c.packageCache, c.maxEntries)
			c.packageCache[key] = response
			c.mu.Unlock()
		case status == http.StatusNotFound:
			c.mu.Lock()
			evictIfFull(c.packageNotFound, c.maxNegativeEntries)
			c.packageNotFound[key] = struct{}{}
			c.mu.Unlock()
		case status >= 500:
			return nil, fmt.Errorf("ecosyste.ms package request for %q failed: %s", key, response.Status())
		}

		return response, nil
	})
	if err != nil {
		return nil, err
	}

	return result.(*packages.GetRegistryPackageResponse), nil
}

func (c *InMemoryCache) GetPackageVersionData(purl packageurl.PackageURL) (*packages.GetRegistryPackageVersionResponse, error) {
	key := purl.ToString()

	c.mu.RLock()
	if cached, exists := c.packageVersionCache[key]; exists {
		c.mu.RUnlock()
		return cached, nil
	}
	_, notFound := c.packageVersionNotFound[key]
	c.mu.RUnlock()
	if notFound {
		return notFoundPackageVersionResponse(), nil
	}

	result, err, _ := c.packageVersionGroup.Do(key, func() (interface{}, error) {
		response, err := GetPackageVersionData(purl)
		if err != nil {
			return nil, err
		}

		switch status := response.StatusCode(); {
		case status >= 200 && status < 300:
			c.mu.Lock()
			evictIfFull(c.packageVersionCache, c.maxEntries)
			c.packageVersionCache[key] = response
			c.mu.Unlock()
		case status == http.StatusNotFound:
			c.mu.Lock()
			evictIfFull(c.packageVersionNotFound, c.maxNegativeEntries)
			c.packageVersionNotFound[key] = struct{}{}
			c.mu.Unlock()
		case status >= 500:
			return nil, fmt.Errorf("ecosyste.ms package version request for %q failed: %s", key, response.Status())
		}

		return response, nil
	})
	if err != nil {
		return nil, err
	}

	return result.(*packages.GetRegistryPackageVersionResponse), nil
}

func (c *InMemoryCache) GetCacheStats() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.packageCache), len(c.packageVersionCache)
}

// evictIfFull makes room for a new entry by evicting an arbitrary existing
// entry once the map has reached max entries. Callers must hold c.mu.
func evictIfFull[V any](m map[string]V, max int) {
	if max <= 0 || len(m) < max {
		return
	}
	for key := range m {
		delete(m, key)
		break
	}
}

func notFoundPackageResponse() *packages.GetRegistryPackageResponse {
	return &packages.GetRegistryPackageResponse{
		HTTPResponse: &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "404 Not Found",
		},
	}
}

func notFoundPackageVersionResponse() *packages.GetRegistryPackageVersionResponse {
	return &packages.GetRegistryPackageVersionResponse{
		HTTPResponse: &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "404 Not Found",
		},
	}
}
