package checks

import (
	"testing"
	"time"
)

func TestResolvePublicIPWithCache(t *testing.T) {
	sample := publicIPResult{
		ip:          testStrPtr("176.104.177.170"),
		country:     testStrPtr("PL"),
		countryName: testStrPtr("Poland"),
		isp:         testStrPtr("FIBERLINK Sp. z o.o."),
		asn:         testStrPtr("AS50767"),
	}

	t.Run("returns fresh cache and skips remote fetch", func(t *testing.T) {
		readCalls := 0
		readCache := func(maxAge time.Duration) publicIPResult {
			readCalls++
			if maxAge != ipapiCacheTTL {
				t.Fatalf("unexpected maxAge: %v", maxAge)
			}
			return sample
		}

		fetchCalls := 0
		fetchRemote := func() publicIPResult {
			fetchCalls++
			return publicIPResult{}
		}

		writeCalls := 0
		writeCache := func(data publicIPResult) {
			writeCalls++
		}

		failureReadCalls := 0
		hasRecentFailure := func(maxAge time.Duration) bool {
			failureReadCalls++
			return false
		}
		markFailureCalls := 0
		markFailure := func() {
			markFailureCalls++
		}
		clearFailureCalls := 0
		clearFailure := func() {
			clearFailureCalls++
		}

		result := resolvePublicIPWithCache(
			readCache,
			fetchRemote,
			writeCache,
			hasRecentFailure,
			markFailure,
			clearFailure,
		)

		if result.ip == nil || *result.ip != *sample.ip {
			t.Fatalf("expected cached result")
		}
		if readCalls != 1 {
			t.Fatalf("expected read cache once, got %d", readCalls)
		}
		if fetchCalls != 0 {
			t.Fatalf("expected fetch not called, got %d", fetchCalls)
		}
		if writeCalls != 0 {
			t.Fatalf("expected write not called, got %d", writeCalls)
		}
		if failureReadCalls != 0 {
			t.Fatalf("expected no failure-cache reads, got %d", failureReadCalls)
		}
		if markFailureCalls != 0 {
			t.Fatalf("expected no failure marks, got %d", markFailureCalls)
		}
		if clearFailureCalls != 0 {
			t.Fatalf("expected no failure clears, got %d", clearFailureCalls)
		}
	})

	t.Run("fetches remote and writes cache when fresh cache is missing", func(t *testing.T) {
		readCalls := 0
		readCache := func(maxAge time.Duration) publicIPResult {
			readCalls++
			return publicIPResult{}
		}

		fetchCalls := 0
		fetchRemote := func() publicIPResult {
			fetchCalls++
			return sample
		}

		writeCalls := 0
		writeCache := func(data publicIPResult) {
			writeCalls++
		}

		failureReadCalls := 0
		hasRecentFailure := func(maxAge time.Duration) bool {
			failureReadCalls++
			return false
		}
		markFailureCalls := 0
		markFailure := func() {
			markFailureCalls++
		}
		clearFailureCalls := 0
		clearFailure := func() {
			clearFailureCalls++
		}

		result := resolvePublicIPWithCache(
			readCache,
			fetchRemote,
			writeCache,
			hasRecentFailure,
			markFailure,
			clearFailure,
		)

		if result.ip == nil || *result.ip != *sample.ip {
			t.Fatalf("expected fetched result")
		}
		if readCalls != 1 {
			t.Fatalf("expected one read (fresh only), got %d", readCalls)
		}
		if fetchCalls != 1 {
			t.Fatalf("expected fetch once, got %d", fetchCalls)
		}
		if writeCalls != 1 {
			t.Fatalf("expected write once, got %d", writeCalls)
		}
		if failureReadCalls != 1 {
			t.Fatalf("expected one failure-cache read, got %d", failureReadCalls)
		}
		if markFailureCalls != 0 {
			t.Fatalf("expected no failure marks, got %d", markFailureCalls)
		}
		if clearFailureCalls != 1 {
			t.Fatalf("expected one failure clear, got %d", clearFailureCalls)
		}
	})

	t.Run("falls back to stale cache when remote fetch fails", func(t *testing.T) {
		readCalls := 0
		readCache := func(maxAge time.Duration) publicIPResult {
			readCalls++
			if readCalls == 1 && maxAge != ipapiCacheTTL {
				t.Fatalf("expected fresh cache TTL, got %v", maxAge)
			}
			if readCalls == 2 && maxAge != ipapiStaleIfErrorTTL {
				t.Fatalf("expected stale cache TTL, got %v", maxAge)
			}
			if readCalls == 2 {
				return sample
			}
			return publicIPResult{}
		}

		fetchCalls := 0
		fetchRemote := func() publicIPResult {
			fetchCalls++
			return publicIPResult{}
		}

		writeCalls := 0
		writeCache := func(data publicIPResult) {
			writeCalls++
		}

		failureReadCalls := 0
		hasRecentFailure := func(maxAge time.Duration) bool {
			failureReadCalls++
			return false
		}
		markFailureCalls := 0
		markFailure := func() {
			markFailureCalls++
		}
		clearFailureCalls := 0
		clearFailure := func() {
			clearFailureCalls++
		}

		result := resolvePublicIPWithCache(
			readCache,
			fetchRemote,
			writeCache,
			hasRecentFailure,
			markFailure,
			clearFailure,
		)

		if result.ip == nil || *result.ip != *sample.ip {
			t.Fatalf("expected stale cache result")
		}
		if readCalls != 2 {
			t.Fatalf("expected two cache reads, got %d", readCalls)
		}
		if fetchCalls != 1 {
			t.Fatalf("expected one fetch, got %d", fetchCalls)
		}
		if writeCalls != 0 {
			t.Fatalf("expected no writes, got %d", writeCalls)
		}
		if failureReadCalls != 1 {
			t.Fatalf("expected one failure-cache read, got %d", failureReadCalls)
		}
		if markFailureCalls != 1 {
			t.Fatalf("expected one failure mark, got %d", markFailureCalls)
		}
		if clearFailureCalls != 0 {
			t.Fatalf("expected no failure clears, got %d", clearFailureCalls)
		}
	})

	t.Run("uses stale cache and skips remote fetch when recent failure is cached", func(t *testing.T) {
		readCalls := 0
		readCache := func(maxAge time.Duration) publicIPResult {
			readCalls++
			if readCalls == 1 && maxAge != ipapiCacheTTL {
				t.Fatalf("expected fresh cache TTL, got %v", maxAge)
			}
			if readCalls == 2 && maxAge != ipapiStaleIfErrorTTL {
				t.Fatalf("expected stale cache TTL, got %v", maxAge)
			}
			if readCalls == 2 {
				return sample
			}
			return publicIPResult{}
		}

		fetchCalls := 0
		fetchRemote := func() publicIPResult {
			fetchCalls++
			return sample
		}

		writeCalls := 0
		writeCache := func(data publicIPResult) {
			writeCalls++
		}

		failureReadCalls := 0
		hasRecentFailure := func(maxAge time.Duration) bool {
			failureReadCalls++
			if maxAge != ipapiNegativeCacheTTL {
				t.Fatalf("unexpected negative-cache TTL: %v", maxAge)
			}
			return true
		}
		markFailureCalls := 0
		markFailure := func() {
			markFailureCalls++
		}
		clearFailureCalls := 0
		clearFailure := func() {
			clearFailureCalls++
		}

		result := resolvePublicIPWithCache(
			readCache,
			fetchRemote,
			writeCache,
			hasRecentFailure,
			markFailure,
			clearFailure,
		)

		if result.ip == nil || *result.ip != *sample.ip {
			t.Fatalf("expected stale cache result")
		}
		if readCalls != 2 {
			t.Fatalf("expected two cache reads, got %d", readCalls)
		}
		if fetchCalls != 0 {
			t.Fatalf("expected no remote fetches, got %d", fetchCalls)
		}
		if writeCalls != 0 {
			t.Fatalf("expected no writes, got %d", writeCalls)
		}
		if failureReadCalls != 1 {
			t.Fatalf("expected one failure-cache read, got %d", failureReadCalls)
		}
		if markFailureCalls != 0 {
			t.Fatalf("expected no failure marks, got %d", markFailureCalls)
		}
		if clearFailureCalls != 0 {
			t.Fatalf("expected no failure clears, got %d", clearFailureCalls)
		}
	})
}

func testStrPtr(v string) *string {
	return &v
}
