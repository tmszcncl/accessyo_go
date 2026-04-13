package commands

import (
	"reflect"
	"testing"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

func TestGetClientVarianceInfo(t *testing.T) {
	t.Run("returns neutral info when browser response differs", func(t *testing.T) {
		browserDiffers := true
		browserStatus := 403
		result := &types.HttpResult{
			Ok:                true,
			DurationMs:        120,
			StatusCode:        intPtr(200),
			Redirects:         []string{},
			Headers:           map[string]string{},
			BrowserDiffers:    &browserDiffers,
			BrowserStatusCode: &browserStatus,
		}

		info := getClientVarianceInfo(result)
		expected := &clientVarianceInfo{
			title:   "response varies by client",
			details: []string{"server may treat CLI and browsers differently"},
		}
		if !reflect.DeepEqual(info, expected) {
			t.Fatalf("unexpected info: %+v", info)
		}
	})

	t.Run("returns nil when responses do not differ", func(t *testing.T) {
		browserDiffers := false
		result := &types.HttpResult{
			Ok:             true,
			DurationMs:     120,
			StatusCode:     intPtr(200),
			Redirects:      []string{},
			Headers:        map[string]string{},
			BrowserDiffers: &browserDiffers,
		}
		if info := getClientVarianceInfo(result); info != nil {
			t.Fatalf("expected nil, got %+v", info)
		}
		if info := getClientVarianceInfo(nil); info != nil {
			t.Fatalf("expected nil for nil result, got %+v", info)
		}
	})
}
