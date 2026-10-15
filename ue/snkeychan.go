package ue

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func snKeyChannelAddr() (string, string) {
	addr := os.Getenv("SN_KEY_CHANNEL")
	if addr == "" {
		addr = "/run/l25gc/n3iwf-ue-key.sock"
	}
	if strings.HasPrefix(addr, "/") {
		return "unix", addr
	}
	return "tcp", addr
}

func sendKN3IWFSN(supi string, pduSessionID uint8, kN3iwf []byte) error {
	network, addr := snKeyChannelAddr()
	payload, err := json.Marshal(map[string]interface{}{
		"supi":         supi,
		"pduSessionID": pduSessionID,
		"kN3iwfHex":    hex.EncodeToString(kN3iwf),
	})
	if err != nil {
		return err
	}
	var last error
	for i := 0; i < 10; i++ {
		conn, derr := net.DialTimeout(network, addr, 3*time.Second)
		if derr != nil {
			last = derr
			time.Sleep(time.Second)
			continue
		}
		_, werr := conn.Write(payload)
		conn.Close()
		if werr != nil {
			last = werr
			time.Sleep(time.Second)
			continue
		}
		return nil
	}
	return last
}

// StartSNKeyTrigger delivers the cached K_N3IWF_SN to the co-located n3iwue on
// SIGUSR1 (the MN-anchored "add SN" signal; replaced by the gNB RAN-CP trigger
// in the full merge). It must fire AFTER the AMF has keyed the N3IWF via the
// NR-DC SN-add, so the N3IWF can verify IKE_AUTH.
func StartSNKeyTrigger(supi string, pduSessionID uint8, getKey func() []byte, logf func(string, ...interface{})) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		for range ch {
			key := getKey()
			if len(key) != 32 {
				logf("SN key channel: no cached K_N3IWF_SN yet")
				continue
			}
			if err := sendKN3IWFSN(supi, pduSessionID, key); err != nil {
				logf("SN key channel: send to n3iwue failed: %v", err)
			} else {
				logf("SN key channel: delivered K_N3IWF_SN to n3iwue (SIGUSR1)")
			}
		}
	}()
}
