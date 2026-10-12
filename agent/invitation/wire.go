package invitation

type AgentProfile struct {
	Version          int      `json:"version"`
	Key              string   `json:"key"`
	WireGuardKey     string   `json:"wireGuardKey"`
	Name             *string  `json:"name,omitempty"`
	Platform         *string  `json:"platform,omitempty"`
	OverlayAddresses []string `json:"overlayAddresses"`
	ConnectedAt      string   `json:"connectedAt"`
}

type AppleBootstrapStatus struct {
	Version          int           `json:"version"`
	AssignmentID     string        `json:"assignmentId"`
	TokenDigest      string        `json:"tokenDigest"`
	TransactionID    string        `json:"transactionId"`
	TunnelInstanceID string        `json:"tunnelInstanceId"`
	Generation       uint64        `json:"generation"`
	State            string        `json:"state"`
	UpdatedAt        string        `json:"updatedAt"`
	Error            *NetworkError `json:"error,omitempty"`
}

type NetworkError struct {
	Version   int            `json:"version"`
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}
