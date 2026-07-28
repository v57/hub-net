package dnsresolver

// NewPlatformInstaller returns the host split-DNS installer. Unsupported
// platforms return an installer whose Install fails closed.
func NewPlatformInstaller(interfaceName string) Installer {
	return newPlatformInstaller(interfaceName)
}
