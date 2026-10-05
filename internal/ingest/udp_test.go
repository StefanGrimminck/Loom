package ingest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/honeylabshq/Loom/internal/ratelimit"
)

func udpEvents() []map[string]interface{} {
	dns := spipStyleEvent("198.51.100.7", "sensor-a")
	dns["network"] = map[string]interface{}{"transport": "udp", "protocol": "dns"}
	dns["dns"] = map[string]interface{}{
		"id": "43981", "op_code": "QUERY", "type": "query",
		"question": map[string]interface{}{"name": "example.com", "type": "ANY", "class": "IN"},
		"edns":     map[string]interface{}{"udp_size": float64(4096), "do": true},
	}
	quic := spipStyleEvent("198.51.100.8", "sensor-a")
	quic["network"] = map[string]interface{}{"transport": "udp", "protocol": "quic"}
	quic["tls"] = map[string]interface{}{"client": map[string]interface{}{
		"server_name": "victim.example",
		"hash":        map[string]interface{}{"ja4": "q13d0313h3_55b375c5d22e_19cb63ff0383"},
	}}
	quic["quic"] = map[string]interface{}{
		"version": "1", "dcid": "0102030405060708", "hello_complete": true, "datagrams": float64(2),
		"client": map[string]interface{}{"transport_parameters": map[string]interface{}{"hash": "9fa2f999e2f4"}},
	}
	return []map[string]interface{}{dns, quic}
}

func post(t *testing.T, h *Handler, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUDPEventsPassThroughUnchanged(t *testing.T) {
	h := makeTestHandler(t)
	var got []map[string]interface{}
	h.ProcessBatch = func(_ string, ev []map[string]interface{}) error { got = ev; return nil }
	want := udpEvents()
	rec := post(t, h, mustJSON(want), "application/json")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events changed in transit:\n got %v\nwant %v", got, want)
	}
}

func TestContentTypeParametersAccepted(t *testing.T) {
	h := makeTestHandler(t)
	if rec := post(t, h, []byte("[]"), "application/json; charset=utf-8"); rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if rec := post(t, h, []byte("[]"), "application/jsonx"); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestEventRateLimit(t *testing.T) {
	h := makeTestHandler(t)
	h.MaxEvents = 2
	h.EventLimiter = ratelimit.NewEventLimiter(1, 2)
	body := mustJSON(udpEvents())
	if rec := post(t, h, body, "application/json"); rec.Code != http.StatusNoContent {
		t.Fatalf("first batch: %d", rec.Code)
	}
	rec := post(t, h, body, "application/json")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("second batch: %d", rec.Code)
	}
}
