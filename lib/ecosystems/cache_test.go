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
	"sync/atomic"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryCache_GetPackageData(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	mockResponse := `{"name": "test-package", "description": "Test package"}`
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, mockResponse),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	resp1, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.NotNil(t, resp1)

	resp2, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.NotNil(t, resp2)
	assert.Equal(t, resp1, resp2)

	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 1, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 1, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)
}

func TestInMemoryCache_GetPackageVersionData(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	mockResponse := `{"number": "1.0.0", "licenses": "MIT"}`
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, mockResponse),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	resp1, err := cache.GetPackageVersionData(purl)
	assert.NoError(t, err)
	assert.NotNil(t, resp1)

	resp2, err := cache.GetPackageVersionData(purl)
	assert.NoError(t, err)
	assert.NotNil(t, resp2)
	assert.Equal(t, resp1, resp2)

	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 1, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 0, pkgCacheSize)
	assert.Equal(t, 1, versionCacheSize)
}

func TestInMemoryCache_DifferentPackages(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, `{}`),
	)

	cache := NewInMemoryCache()
	purl1, err := packageurl.FromString("pkg:npm/package1@1.0.0")
	require.NoError(t, err)
	purl2, err := packageurl.FromString("pkg:npm/package2@1.0.0")
	require.NoError(t, err)

	_, err = cache.GetPackageData(purl1)
	assert.NoError(t, err)
	_, err = cache.GetPackageData(purl2)
	assert.NoError(t, err)

	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 2, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 2, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)
}

func TestInMemoryCache_SamePackageDifferentVersions(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, `{}`),
	)

	cache := NewInMemoryCache()
	purl1, err := packageurl.FromString("pkg:npm/package@1.0.0")
	require.NoError(t, err)
	purl2, err := packageurl.FromString("pkg:npm/package@2.0.0")
	require.NoError(t, err)

	_, err = cache.GetPackageData(purl1)
	assert.NoError(t, err)
	_, err = cache.GetPackageData(purl2)
	assert.NoError(t, err)

	// Different versions = different cache entries
	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 2, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 2, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)
}

func TestInMemoryCache_APIError(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// 5xx responses must surface an error and must never be cached, so that
	// transient upstream failures don't poison the process-level cache.
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(500, `{"error": "internal server error"}`),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	resp1, err := cache.GetPackageData(purl)
	assert.Error(t, err)
	assert.Nil(t, resp1)

	resp2, err := cache.GetPackageData(purl)
	assert.Error(t, err)
	assert.Nil(t, resp2)

	// 5xx responses are not cached: the second call retries upstream
	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 2, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 0, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)
}

func TestInMemoryCache_5xxNotCachedThenRecovers(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// First the upstream fails with 503, then it recovers with a 200. The
	// failure must not poison the cache: the retry should fetch fresh data.
	var calls atomic.Int32
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return httpmock.NewStringResponse(503, `{"error": "service unavailable"}`), nil
			}
			resp := httpmock.NewStringResponse(200, `{"name": "test-package"}`)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	resp, err := cache.GetPackageData(purl)
	assert.Error(t, err)
	assert.Nil(t, resp)

	resp, err = cache.GetPackageData(purl)
	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode())
	require.NotNil(t, resp.JSON200)

	// The recovered 2xx response is now cached
	resp2, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.Equal(t, resp, resp2)
	assert.Equal(t, int32(2), calls.Load())

	pkgCacheSize, _ := cache.GetCacheStats()
	assert.Equal(t, 1, pkgCacheSize)
}

func TestInMemoryCache_VersionData5xxNotCached(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(502, `{"error": "bad gateway"}`),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	resp, err := cache.GetPackageVersionData(purl)
	assert.Error(t, err)
	assert.Nil(t, resp)

	resp, err = cache.GetPackageVersionData(purl)
	assert.Error(t, err)
	assert.Nil(t, resp)

	assert.Equal(t, 2, httpmock.GetTotalCallCount())

	_, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 0, versionCacheSize)
}

func TestInMemoryCache_404NotFound(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// HTTP client returns a successful response even with 404 status
	// We want to cache 404 responses to avoid hammering the server
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(404, `{"error": "not found"}`),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:golang/stdlib@1.0.0")
	require.NoError(t, err)

	// HTTP client doesn't treat 404 as error
	resp1, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.Equal(t, 404, resp1.StatusCode())

	resp2, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.Equal(t, 404, resp2.StatusCode())
	assert.Nil(t, resp2.JSON200)

	// Second call should use cache - only 1 API call total
	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 1, callCount, "Expected only 1 API call, but got %d. 404 responses should be cached.", callCount)

	// 404s live in the bounded negative cache, not the positive cache
	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 0, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)

	cache.mu.RLock()
	negativeSize := len(cache.packageNotFound)
	cache.mu.RUnlock()
	assert.Equal(t, 1, negativeSize)
}

func TestInMemoryCache_404NotFoundVersionData(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Test that 404 responses are also cached for version data
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(404, `{"error": "not found"}`),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:golang/stdlib@1.0.0")
	require.NoError(t, err)

	// HTTP client doesn't treat 404 as error
	resp1, err := cache.GetPackageVersionData(purl)
	assert.NoError(t, err)
	assert.Equal(t, 404, resp1.StatusCode())

	resp2, err := cache.GetPackageVersionData(purl)
	assert.NoError(t, err)
	assert.Equal(t, 404, resp2.StatusCode())
	assert.Nil(t, resp2.JSON200)

	// Second call should use cache - only 1 API call total
	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 1, callCount, "Expected only 1 API call, but got %d. 404 responses should be cached.", callCount)

	// 404s live in the bounded negative cache, not the positive cache
	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 0, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)

	cache.mu.RLock()
	negativeSize := len(cache.packageVersionNotFound)
	cache.mu.RUnlock()
	assert.Equal(t, 1, negativeSize)
}

func TestInMemoryCache_ConcurrentAccess(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, `{}`),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.GetPackageData(purl)
			assert.NoError(t, err)
		}()
	}

	wg.Wait()

	// Should only have one entry despite concurrent access
	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 1, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)

	// API should have been called at least once, but should be much less than 100 due to caching
	// Can't guarantee exactly 1 call due to race conditions, but should be significantly less than numGoroutines
	callCount := httpmock.GetTotalCallCount()
	assert.True(t, callCount >= 1 && callCount < numGoroutines)
}

func TestInMemoryCache_ConcurrentDuplicateRequestsCallUpstreamOnce(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// A slow responder forces the concurrent requests to overlap, so
	// de-duplication (not just fast caching) is what keeps the count at 1.
	var calls atomic.Int32
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			time.Sleep(50 * time.Millisecond)
			return httpmock.NewStringResponse(200, `{"name": "test-package"}`), nil
		},
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := cache.GetPackageData(purl)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), calls.Load(), "concurrent duplicate requests should only hit upstream once")
}

func TestInMemoryCache_BoundedPositiveCache(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, `{}`),
	)

	cache := NewInMemoryCache()
	cache.maxEntries = 3

	for i := 0; i < 10; i++ {
		purl, err := packageurl.FromString(fmt.Sprintf("pkg:npm/package-%d@1.0.0", i))
		require.NoError(t, err)
		_, err = cache.GetPackageData(purl)
		require.NoError(t, err)
	}

	pkgCacheSize, _ := cache.GetCacheStats()
	assert.Equal(t, 3, pkgCacheSize, "positive cache must be bounded")
}

func TestInMemoryCache_BoundedNegativeCache(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(404, `{"error": "not found"}`),
	)

	cache := NewInMemoryCache()
	cache.maxNegativeEntries = 2

	for i := 0; i < 10; i++ {
		purl, err := packageurl.FromString(fmt.Sprintf("pkg:npm/missing-%d@1.0.0", i))
		require.NoError(t, err)
		resp, err := cache.GetPackageData(purl)
		require.NoError(t, err)
		assert.Equal(t, 404, resp.StatusCode())
	}

	cache.mu.RLock()
	negativeSize := len(cache.packageNotFound)
	cache.mu.RUnlock()
	assert.Equal(t, 2, negativeSize, "negative cache must be bounded")
}

func TestInMemoryCache_NegativeCacheHitSkipsUpstream(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(404, `{"error": "not found"}`),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/missing@1.0.0")
	require.NoError(t, err)

	resp1, err := cache.GetPackageData(purl)
	require.NoError(t, err)
	assert.Equal(t, 404, resp1.StatusCode())
	assert.Nil(t, resp1.JSON200)

	resp2, err := cache.GetPackageData(purl)
	require.NoError(t, err)
	assert.Equal(t, 404, resp2.StatusCode())
	assert.Nil(t, resp2.JSON200)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestGetGlobalCache_Singleton(t *testing.T) {
	// GetGlobalCache should return the same instance every time
	cache1 := GetGlobalCache()
	cache2 := GetGlobalCache()

	assert.Equal(t, cache1, cache2, "GetGlobalCache should return the same instance")
}

func TestGetGlobalCache_SharesDataAcrossEnrichments(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Reset global cache for this test
	globalCache = nil
	globalCacheOnce = sync.Once{}

	mockResponse := `{"error": "not found"}`
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(404, mockResponse),
	)

	cache := GetGlobalCache()
	purl, err := packageurl.FromString("pkg:golang/stdlib@1.0.0")
	require.NoError(t, err)

	// First enrichment call
	resp1, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.Equal(t, 404, resp1.StatusCode())

	// Simulate a second enrichment by getting the global cache again
	cache2 := GetGlobalCache()
	resp2, err := cache2.GetPackageData(purl)
	assert.NoError(t, err)
	assert.Equal(t, 404, resp2.StatusCode())

	// Should have only made 1 API call total, because the cache is shared
	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 1, callCount, "Expected only 1 API call across enrichments, but got %d. Global cache should be shared.", callCount)
}
