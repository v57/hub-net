//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/v57/hub-net/config"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "hub-net"

// privateDirSDDL admits LocalSystem and Administrators only, inherited by
// every file below: the state directory holds WireGuard and identity keys,
// and ProgramData would otherwise let every user read them.
const privateDirSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func prepareStateDir(dir string) error {
	return securePrivateDir(dir)
}

func securePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString(privateDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("secure %s: %w", dir, err)
	}
	return nil
}

// defaultDeviceKey is %ProgramData%\hub\device.key for the elevated daemon
// (the Windows counterpart of /var/lib/hub/device.key), unless
// HUB_DEVICE_KEY names one; the directory is made private first.
func defaultDeviceKey() string {
	if os.Getenv("HUB_DEVICE_KEY") != "" || !windows.GetCurrentProcessToken().IsElevated() {
		return ""
	}
	dir := filepath.Join(os.Getenv("ProgramData"), "hub")
	if err := securePrivateDir(dir); err != nil {
		return ""
	}
	return filepath.Join(dir, "device.key")
}

type serviceHandler struct {
	run func(context.Context) error
	log *eventlog.Log
}

func runAsService(run func(context.Context) error) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, nil
	}
	log, _ := eventlog.Open(serviceName)
	// A service has no console: the daemon's log goes to hub-net.log in the
	// default state directory, replaced at each start.
	if dir := config.DefaultStateDir(); securePrivateDir(dir) == nil {
		if file, err := os.Create(filepath.Join(dir, "hub-net.log")); err == nil {
			os.Stderr = file
			defer file.Close()
		}
	}
	handler := &serviceHandler{run: run, log: log}
	err = svc.Run(serviceName, handler)
	if log != nil {
		if err != nil {
			log.Error(1, "hub-net service: "+err.Error())
		}
		log.Close()
	}
	return true, err
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				if h.log != nil {
					h.log.Error(1, "hub-net daemon stopped: "+err.Error())
				}
				// A non-zero exit code lets the recovery actions restart it.
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

// serviceCommand installs, removes, starts or stops the hub-net service.
// install registers hub-net.exe (with daemonFlags) as an automatic
// LocalSystem service that restarts on failure, and starts it.
func serviceCommand(args, daemonFlags []string) error {
	if len(args) != 1 {
		return errors.New("usage: hub-net [daemon flags] service install|uninstall|start|stop")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run from an elevated shell): %w", err)
	}
	defer manager.Disconnect()
	switch args[0] {
	case "install":
		return installService(manager, daemonFlags)
	case "uninstall":
		return uninstallService(manager)
	case "start":
		service, err := manager.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer service.Close()
		return service.Start()
	case "stop":
		service, err := manager.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer service.Close()
		return stopService(service)
	}
	return fmt.Errorf("service: unknown command %q", args[0])
}

func installService(manager *mgr.Mgr, daemonFlags []string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(executable), "wireguard.dll")); err != nil {
		return fmt.Errorf("service: wireguard.dll must sit next to %s: %w", executable, err)
	}
	if existing, err := manager.OpenService(serviceName); err == nil {
		existing.Close()
		return errors.New("service: hub-net is already installed (hub-net service uninstall first)")
	}
	service, err := manager.CreateService(serviceName, executable, mgr.Config{
		DisplayName:  "Hub Network",
		Description:  "Hub Network agent: joins this device to Hub networks (WireGuardNT).",
		StartType:    mgr.StartAutomatic,
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		Dependencies: []string{"Nsi", "TcpIp", "BFE"},
	}, daemonFlags...)
	if err != nil {
		return err
	}
	defer service.Close()
	err = service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*60*60)
	if err == nil {
		err = service.SetRecoveryActionsOnNonCrashFailures(true)
	}
	if err != nil {
		service.Delete()
		return err
	}
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil && !strings.Contains(err.Error(), "exists") {
		service.Delete()
		return err
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("service installed but not started: %w", err)
	}
	fmt.Println("Installed and started the hub-net service")
	return nil
}

func uninstallService(manager *mgr.Mgr) error {
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service: hub-net is not installed: %w", err)
	}
	defer service.Close()
	if err := stopService(service); err != nil {
		return err
	}
	if err := service.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(serviceName)
	fmt.Println("Removed the hub-net service")
	return nil
}

func stopService(service *mgr.Service) error {
	status, err := service.Control(svc.Stop)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return errors.New("service: hub-net didn't stop within 30 s")
		}
		time.Sleep(300 * time.Millisecond)
		if status, err = service.Query(); err != nil {
			return err
		}
	}
	return nil
}
