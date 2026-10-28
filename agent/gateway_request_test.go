package hubnet

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	channelgo "github.com/v57/channel-go/channelgo"
)

// silentHub accepts requests and never answers them, like a hub that holds
// network/gateway/advertise.
type silentHub struct {
	mu        sync.Mutex
	sent      int
	cancelled int
}

func (h *silentHub) Send(any) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sent++
	return h.sent
}
func (h *silentHub) Sent(int) {}
func (h *silentHub) Cancel(int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cancelled++
	return true
}
func (h *silentHub) Notify(any) {}
func (h *silentHub) AddTopic(string, channelgo.EventBody) func() bool {
	return func() bool { return true }
}
func (h *silentHub) Stop() {}

func TestSendWithinGivesUpOnAHubThatNeverAnswers(t *testing.T) {
	hub := &silentHub{}
	sender := channelgo.MakeSender(channelgo.NewChannel(), hub)
	started := time.Now()
	_, err := sendWithin(context.Background(), sender, 50*time.Millisecond, "network/gateway/advertise", map[string]any{})
	if !errors.Is(err, errHubDidNotAnswer) {
		t.Fatalf("err = %v, want errHubDidNotAnswer", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("waited %s", elapsed)
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if hub.sent != 1 || hub.cancelled != 1 {
		t.Fatalf("sent %d cancelled %d, want the request sent once and cancelled", hub.sent, hub.cancelled)
	}
}

func TestSendWithinStopsWithItsContext(t *testing.T) {
	sender := channelgo.MakeSender(channelgo.NewChannel(), &silentHub{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sendWithin(ctx, sender, time.Minute, "network/gateway/remove", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
