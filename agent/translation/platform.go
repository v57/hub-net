package translation

// NewPlatformBackend returns host route probing, policy routing, and
// reversible translation for the current platform.
func NewPlatformBackend() (Backend, error) {
	return newPlatformBackend()
}
