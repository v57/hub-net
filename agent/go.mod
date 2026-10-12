module github.com/v57/hub-net

go 1.25.0

require (
	github.com/v57/channel-go v0.1.0
	github.com/v57/hub-net-node v0.0.0
	github.com/v57/hub-service-go v0.1.0
	golang.org/x/sys v0.22.0
)

replace github.com/v57/channel-go => ../../channel-go

replace github.com/v57/hub-net-node => ../../hub-net-node

replace github.com/v57/hub-service-go => ../../hub-service-go

require (
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	golang.org/x/arch v0.0.0-20210923205945-b76863e36670 // indirect
)
