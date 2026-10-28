package peerlink

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"sort"
	"time"

	"github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
)

// Peer is one linked device as WireGuard sees it.
type Peer struct {
	Key          string
	WireGuardKey string
	// Routes are what this device sends through the peer.
	Routes []netip.Prefix
	// Endpoint is the address being tried or found, empty until link.ready.
	Endpoint string
}

func (p Peer) equal(other Peer) bool {
	if p.Key != other.Key || p.WireGuardKey != other.WireGuardKey || p.Endpoint != other.Endpoint ||
		len(p.Routes) != len(other.Routes) {
		return false
	}
	for index := range p.Routes {
		if p.Routes[index] != other.Routes[index] {
			return false
		}
	}
	return true
}

// Opened is the node's answer to link.open.
type Opened struct {
	LinkID     string
	ProbeToken string
	PeerKey    string
}

// Dependencies connect the manager to the node, WireGuard and the host.
type Dependencies struct {
	// Open sends link.open with the grant and returns the node's answer.
	Open func(ctx context.Context, grant models.PeerLinkGrant) (Opened, error)
	// Send sends link.accept, link.reject or link.offer.
	Send func(messageType protocol.MessageType, linkID string, endpoints []models.LinkEndpoint) error
	// Probe sends one datagram to the node from WireGuard's own socket.
	Probe func(ctx context.Context, payload []byte) error
	// Apply installs the linked peers in WireGuard.
	Apply func([]Peer) error
	// LastHandshake reports the latest handshake with the peer of a base64
	// WireGuard key.
	LastHandshake func(wireGuardKey string) (time.Time, bool)
	// Candidates are this device's host candidates for link.offer (LAN,
	// global IPv6) with WireGuard's port.
	Candidates func() []models.LinkEndpoint
	Logger     *slog.Logger
	Now        func() time.Time
}

const (
	// LiveHandshakeAge: a path counts as live while handshakes keep coming
	// (WireGuard renews its session every two minutes).
	LiveHandshakeAge = 150 * time.Second
	endpointTrial    = 5 * time.Second
	punchWindow      = 60 * time.Second
	probeInterval    = time.Second
	// The node closes a link that isn't ready within a minute
	probeRounds = 60
)

type attempt struct {
	link       Link
	probeToken string
	stopProbe  context.CancelFunc
	punching   bool
	stopPunch  context.CancelFunc
}

// Manager runs this device's links. The opening side (`a`) asks the node for
// the link whenever it has no live path; the other side accepts only what it
// verified. Both probe the node from WireGuard's socket, and once link.ready
// arrives they set each other as WireGuard peers and try the other's
// candidates and observed endpoint in turn, so the handshakes from both ends
// open the NAT mappings. All state lives on one goroutine (Run); the
// exported methods post to it.
type Manager struct {
	ownKey string
	deps   Dependencies
	log    *slog.Logger
	now    func() time.Time
	events chan func()
	// done closes when Run returns. ctx is Run's context, set before the
	// first event and read only on the event goroutine (or captured there).
	done chan struct{}
	ctx  context.Context

	trustedHubKey string
	own           []Link
	// admitted are devices that brought a grant this device verified, by key.
	admitted map[string]Link
	peers    map[string]Peer
	attempts map[string]*attempt
	opening  map[string]bool
	// delivered is the grant each linked device last took, by its key: a new
	// grant opens the link again even while the path is live.
	delivered map[string]string
	present   bool
	applied   []Peer
}

// New returns a manager for the device with service key ownKey.
func New(ownKey string, deps Dependencies) *Manager {
	logger := deps.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		ownKey: ownKey, deps: deps, log: logger, now: now,
		events:    make(chan func(), 64),
		done:      make(chan struct{}),
		ctx:       context.Background(),
		admitted:  make(map[string]Link),
		peers:     make(map[string]Peer),
		attempts:  make(map[string]*attempt),
		opening:   make(map[string]bool),
		delivered: make(map[string]string),
	}
}

// Run processes events and the periodic upkeep until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.ctx = ctx
	defer close(m.done)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer m.stopAll()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-m.events:
			event()
		case <-ticker.C:
			m.removeStale()
			m.openWhereNeeded()
		}
	}
}

func (m *Manager) post(event func()) {
	select {
	case m.events <- event:
	case <-m.done:
	}
}

// Update takes the grants the hub issued this device (network/links) and the
// hub key this device pinned; the grants that don't verify are dropped.
func (m *Manager) Update(trustedHubKey string, grants []models.PeerLinkGrant) {
	m.post(func() {
		m.trustedHubKey = trustedHubKey
		var verified []Link
		for _, grant := range grants {
			link, err := Verify(grant, trustedHubKey, m.ownKey, m.now())
			if err != nil {
				m.log.Warn("link grant rejected", slog.String("grant", short(grant.GrantID)), slog.String("err", err.Error()))
				continue
			}
			verified = append(verified, link)
		}
		m.own = verified
		for _, link := range verified {
			m.setPeer(link)
		}
		m.removeStale()
		m.openWhereNeeded()
	})
}

// PresenceChanged is told when this device's presence came (a fresh
// registration: the node knows no links of it) or went.
func (m *Manager) PresenceChanged(present bool) {
	m.post(func() {
		m.present = present
		if !present {
			for id, current := range m.attempts {
				current.stopProbe()
				if current.stopPunch != nil {
					current.stopPunch()
				}
				delete(m.attempts, id)
			}
			m.opening = make(map[string]bool)
			return
		}
		m.openWhereNeeded()
	})
}

// Handle takes the node's link pushes: link.incoming, link.ready,
// link.closed and errors about a link.
func (m *Manager) Handle(envelope protocol.Envelope) {
	m.post(func() {
		switch envelope.Type {
		case protocol.MessageLinkIncoming:
			m.incoming(envelope)
		case protocol.MessageLinkReady:
			m.ready(envelope)
		case protocol.MessageLinkClosed, protocol.MessageError:
			current, ok := m.attempts[envelope.LinkID]
			if !ok {
				return
			}
			current.stopProbe()
			// A punch already running keeps going: the devices hold the path
			// themselves
			if !current.punching {
				delete(m.attempts, envelope.LinkID)
				code := "?"
				if envelope.Error != nil {
					code = envelope.Error.Code
				}
				m.log.Info("link closed", slog.String("link", short(envelope.LinkID)), slog.String("code", code))
			}
		}
	})
}

// Peers reports the linked peers, for status.
func (m *Manager) Peers() []Peer {
	answer := make(chan []Peer, 1)
	m.post(func() { answer <- m.sortedPeers() })
	select {
	case peers := <-answer:
		return peers
	case <-m.done:
		return nil
	case <-time.After(5 * time.Second):
		return nil
	}
}

func (m *Manager) incoming(envelope protocol.Envelope) {
	if envelope.Grant == nil || envelope.LinkID == "" || envelope.ProbeToken == "" || envelope.PeerKey == "" {
		return
	}
	link, err := Verify(*envelope.Grant, m.trustedHubKey, m.ownKey, m.now())
	if err == nil && link.Other.Key != envelope.PeerKey {
		err = ErrNotASide
	}
	if err != nil {
		m.log.Warn("link.incoming rejected", slog.String("link", short(envelope.LinkID)),
			slog.String("from", tail(envelope.PeerKey)), slog.String("err", err.Error()))
		go m.send(protocol.MessageLinkReject, envelope.LinkID, nil)
		return
	}
	m.admitted[envelope.PeerKey] = link
	m.setPeer(link)
	m.apply(false)
	m.log.Info("link.incoming accepted", slog.String("link", short(envelope.LinkID)), slog.String("from", tail(envelope.PeerKey)))
	if err := m.deps.Send(protocol.MessageLinkAccept, envelope.LinkID, nil); err != nil {
		m.log.Warn("link.accept failed", slog.String("err", err.Error()))
		return
	}
	m.begin(envelope.LinkID, link, envelope.ProbeToken)
}

func (m *Manager) ready(envelope protocol.Envelope) {
	current, ok := m.attempts[envelope.LinkID]
	if !ok {
		return
	}
	current.stopProbe()
	endpoints := append([]models.LinkEndpoint(nil), envelope.Endpoints...)
	if envelope.Observed != nil && envelope.Observed.Port != 0 {
		endpoints = append(endpoints, models.LinkEndpoint{Address: envelope.Observed.Address, Port: envelope.Observed.Port})
	}
	punchAt := m.now()
	if parsed, err := time.Parse(time.RFC3339Nano, envelope.PunchAt); err == nil {
		punchAt = parsed
	}
	if current.stopPunch != nil {
		current.stopPunch()
	}
	ctx, cancel := context.WithCancel(m.ctx)
	current.punching = true
	current.stopPunch = cancel
	own := m.candidates()
	var valid []models.LinkEndpoint
	for _, endpoint := range unique(endpoints) {
		if endpointString(endpoint) != "" {
			valid = append(valid, endpoint)
		}
	}
	ordered := ReachableFirst(valid, own)
	linkID := envelope.LinkID
	link := current.link
	// A link opened again for a new grant over a path that still works keeps
	// its endpoint
	if peer, ok := m.peers[link.Other.Key]; ok && peer.Endpoint != "" && m.isLive(link) {
		for _, endpoint := range ordered {
			if endpointString(endpoint) == peer.Endpoint {
				m.delivered[link.Other.Key] = link.Grant.GrantID
				m.log.Info("link renewed", slog.String("link", short(linkID)), slog.String("peer", tail(link.Other.Key)), slog.String("at", peer.Endpoint))
				m.finish(linkID)
				return
			}
		}
	}
	if len(ordered) == 0 {
		return
	}
	go m.punch(ctx, linkID, link, ordered, punchAt)
}

// punch tries each endpoint until a handshake with the peer completes, from
// punchAt on, for up to punchWindow. It runs off the event goroutine.
func (m *Manager) punch(ctx context.Context, linkID string, link Link, endpoints []models.LinkEndpoint, punchAt time.Time) {
	if wait := punchAt.Sub(m.now()); wait > 0 {
		if wait > 5*time.Second {
			wait = 5 * time.Second
		}
		if !sleep(ctx, wait) {
			return
		}
	}
	started := m.now()
	deadline := started.Add(punchWindow)
	for index := 0; m.now().Before(deadline); index++ {
		endpoint := endpointString(endpoints[index%len(endpoints)])
		m.post(func() {
			peer, ok := m.peers[link.Other.Key]
			if ok && peer.Endpoint != endpoint {
				peer.Endpoint = endpoint
				m.peers[link.Other.Key] = peer
				m.apply(false)
			}
		})
		trialEnd := m.now().Add(endpointTrial)
		if trialEnd.After(deadline) {
			trialEnd = deadline
		}
		for m.now().Before(trialEnd) {
			if last, ok := m.deps.LastHandshake(link.Other.WireGuardKey); ok && !last.Before(started.Add(-time.Second)) {
				m.post(func() {
					m.delivered[link.Other.Key] = link.Grant.GrantID
					m.log.Info("link up", slog.String("link", short(linkID)), slog.String("peer", tail(link.Other.Key)), slog.String("at", endpoint))
					m.finish(linkID)
				})
				return
			}
			if !sleep(ctx, 250*time.Millisecond) {
				return
			}
		}
	}
	m.post(func() {
		m.log.Warn("link found no path", slog.String("link", short(linkID)), slog.String("peer", tail(link.Other.Key)))
		m.finish(linkID)
	})
}

func (m *Manager) openWhereNeeded() {
	if !m.present || m.deps.Open == nil {
		return
	}
	for _, link := range m.own {
		if !link.Opens || m.opening[link.Grant.GrantID] {
			continue
		}
		busy := false
		for _, current := range m.attempts {
			if current.link.Grant.GrantID == link.Grant.GrantID {
				busy = true
				break
			}
		}
		if busy || (m.delivered[link.Other.Key] == link.Grant.GrantID && m.isLive(link)) {
			continue
		}
		m.opening[link.Grant.GrantID] = true
		link := link
		ctx := m.ctx
		go func() {
			opened, err := m.deps.Open(ctx, link.Grant)
			m.post(func() {
				delete(m.opening, link.Grant.GrantID)
				if err != nil {
					m.log.Info("link.open failed", slog.String("peer", tail(link.Other.Key)), slog.String("err", err.Error()))
					return
				}
				m.log.Info("link opened", slog.String("link", short(opened.LinkID)), slog.String("peer", tail(opened.PeerKey)))
				m.begin(opened.LinkID, link, opened.ProbeToken)
			})
		}()
	}
}

// begin probes until the link is ready and offers this device's host
// candidates.
func (m *Manager) begin(linkID string, link Link, probeToken string) {
	payload, _ := json.Marshal(protocol.LinkUDPProbe{Version: models.WireVersion, LinkID: linkID, ProbeToken: probeToken})
	ctx, cancel := context.WithCancel(m.ctx)
	m.attempts[linkID] = &attempt{link: link, probeToken: probeToken, stopProbe: cancel}
	go func() {
		for round := 0; round < probeRounds; round++ {
			if err := m.deps.Probe(ctx, payload); err != nil && round == 0 {
				m.log.Warn("link probe failed", slog.String("err", err.Error()))
			}
			if !sleep(ctx, probeInterval) {
				return
			}
		}
	}()
	if candidates := m.candidates(); len(candidates) > 0 {
		go m.send(protocol.MessageLinkOffer, linkID, candidates)
	}
}

func (m *Manager) send(messageType protocol.MessageType, linkID string, endpoints []models.LinkEndpoint) {
	if err := m.deps.Send(messageType, linkID, endpoints); err != nil {
		m.log.Warn("link message failed", slog.String("type", string(messageType)), slog.String("err", err.Error()))
	}
}

func (m *Manager) candidates() []models.LinkEndpoint {
	if m.deps.Candidates == nil {
		return nil
	}
	candidates := m.deps.Candidates()
	if len(candidates) > 16 {
		candidates = candidates[:16]
	}
	return candidates
}

func (m *Manager) isLive(link Link) bool {
	last, ok := m.deps.LastHandshake(link.Other.WireGuardKey)
	return ok && m.now().Sub(last) < LiveHandshakeAge
}

func (m *Manager) finish(linkID string) {
	current, ok := m.attempts[linkID]
	if !ok {
		return
	}
	current.stopProbe()
	delete(m.attempts, linkID)
}

func (m *Manager) stopAll() {
	for id, current := range m.attempts {
		current.stopProbe()
		if current.stopPunch != nil {
			current.stopPunch()
		}
		delete(m.attempts, id)
	}
}

func (m *Manager) setPeer(link Link) {
	current, ok := m.peers[link.Other.Key]
	endpoint := ""
	if ok && current.WireGuardKey == link.Other.WireGuardKey {
		endpoint = current.Endpoint
	}
	m.peers[link.Other.Key] = Peer{
		Key: link.Other.Key, WireGuardKey: link.Other.WireGuardKey,
		Routes: append([]netip.Prefix(nil), link.Routes...), Endpoint: endpoint,
	}
}

func (m *Manager) removeStale() {
	now := m.now()
	own := m.own[:0]
	for _, link := range m.own {
		if link.ExpiresAt.After(now) {
			own = append(own, link)
		}
	}
	m.own = own
	keep := make(map[string]bool)
	for _, link := range m.own {
		keep[link.Other.Key] = true
	}
	for key, link := range m.admitted {
		if link.ExpiresAt.After(now) {
			keep[key] = true
		} else {
			delete(m.admitted, key)
		}
	}
	for key := range m.delivered {
		if !keep[key] {
			delete(m.delivered, key)
		}
	}
	removed := false
	for key := range m.peers {
		if !keep[key] {
			delete(m.peers, key)
			removed = true
		}
	}
	m.apply(removed)
}

func (m *Manager) sortedPeers() []Peer {
	peers := make([]Peer, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Key < peers[j].Key })
	return peers
}

func (m *Manager) apply(force bool) {
	next := m.sortedPeers()
	if !force && m.applied != nil && len(next) == len(m.applied) {
		same := true
		for index := range next {
			if !next[index].equal(m.applied[index]) {
				same = false
				break
			}
		}
		if same {
			return
		}
	}
	if m.deps.Apply == nil {
		return
	}
	if err := m.deps.Apply(next); err != nil {
		m.log.Warn("link peers not applied", slog.String("err", err.Error()))
		return
	}
	m.applied = next
}

// ReachableFirst orders endpoints so a private address of another network
// (a LAN seen from a phone on cellular) goes last: it can't answer, and
// trying it first costs a trial while the other side tries the public
// mapping. Both sides order alike, so they try the same path at once.
func ReachableFirst(endpoints, own []models.LinkEndpoint) []models.LinkEndpoint {
	var near, foreign []models.LinkEndpoint
	for _, endpoint := range endpoints {
		address, err := netip.ParseAddr(endpoint.Address)
		if err != nil || !address.Unmap().Is4() || !isPrivate(address.Unmap()) {
			near = append(near, endpoint)
			continue
		}
		same := false
		for _, mine := range own {
			if mineAddress, err := netip.ParseAddr(mine.Address); err == nil && mineAddress.Unmap().Is4() &&
				sameSubnet(mineAddress.Unmap(), address.Unmap()) {
				same = true
				break
			}
		}
		if same {
			near = append(near, endpoint)
		} else {
			foreign = append(foreign, endpoint)
		}
	}
	return append(near, foreign...)
}

// isPrivate: 10/8, 172.16/12, 192.168/16, 100.64/10 (carrier NAT), 169.254/16
func isPrivate(address netip.Addr) bool {
	bytes := address.As4()
	switch {
	case bytes[0] == 10, bytes[0] == 192 && bytes[1] == 168, bytes[0] == 169 && bytes[1] == 254:
		return true
	case bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31, bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127:
		return true
	}
	return false
}

// sameSubnet: the same /24, as home networks are
func sameSubnet(a, b netip.Addr) bool {
	x, y := a.As4(), b.As4()
	return x[0] == y[0] && x[1] == y[1] && x[2] == y[2]
}

func unique(endpoints []models.LinkEndpoint) []models.LinkEndpoint {
	seen := make(map[models.LinkEndpoint]bool)
	out := endpoints[:0:0]
	for _, endpoint := range endpoints {
		if !seen[endpoint] {
			seen[endpoint] = true
			out = append(out, endpoint)
		}
	}
	return out
}

func endpointString(endpoint models.LinkEndpoint) string {
	address, err := netip.ParseAddr(endpoint.Address)
	if err != nil {
		return ""
	}
	return netip.AddrPortFrom(address.Unmap(), endpoint.Port).String()
}

func sleep(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func short(value string) string {
	if len(value) > 8 {
		return value[:8]
	}
	return value
}

func tail(value string) string {
	if len(value) > 8 {
		return value[len(value)-8:]
	}
	return value
}

// attemptCount reports the links being set up, for tests.
func (m *Manager) attemptCount() int {
	answer := make(chan int, 1)
	m.post(func() { answer <- len(m.attempts) })
	select {
	case count := <-answer:
		return count
	case <-m.done:
		return 0
	}
}

// Reapply installs the linked peers again, after the interface was
// recreated and lost them.
func (m *Manager) Reapply() {
	m.post(func() { m.apply(true) })
}
