package vpn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/machgo/packetstats/pkg/flow"
)

type VPNSessions []struct {
	IPAddress string   `json:"IPAddressToString"`
	Username  []string `json:"Username"`
}

var sessionMap map[string]string
var lock = sync.RWMutex{}

func GetVPNSessions() {
	for {
		sessions := &VPNSessions{}

		//cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "Get-Content remotesessions.json")
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "Get-RemoteAccessConnectionStatistics | select -expand ClientIPAddress -Property Username | select Username, IPAddressToString | convertto-json")

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		cmd.Run()

		json.Unmarshal(stdout.Bytes(), sessions)

		lock.Lock()
		sessionMap = make(map[string]string)

		for _, v := range *sessions {
			sessionMap[v.IPAddress] = v.Username[0]
		}
		lock.Unlock()

		time.Sleep(30000)
	}
}

func FillSessionName(flow *flow.Flow) {
	lock.RLock()
	asdf := string(flow.IPB)
	fmt.Println(asdf)
	fmt.Println(sessionMap)

	fmt.Println(asdf)
	if val, exists := sessionMap[string(flow.IPA)]; exists {
		flow.VPNSession = val
	}
	if val, exists := sessionMap[string(flow.IPB)]; exists {
		flow.VPNSession = val
	}
	if flow.VPNSession == "" {
		flow.VPNSession = "none"
	}

	lock.RUnlock()
}
