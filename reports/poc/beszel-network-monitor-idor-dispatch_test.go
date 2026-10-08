//go:build testing

package systems

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blang/semver"
	"github.com/henrygd/beszel/internal/common"
	"github.com/henrygd/beszel/internal/entities/monitor"
	"github.com/henrygd/beszel/internal/hub/ws"
	"github.com/lxzan/gws"
	"github.com/pocketbase/pocketbase/core"
	"github.com/stretchr/testify/require"
)

// TestNetworkMonitorIDOR_ReachesVictimAgent_PoC proves the downstream impact of the
// network_monitors reassignment IDOR: a monitor row stored on a victim's system
// (exactly what the API-level IDOR produces) is pushed to that system's agent on
// connect, with NO owner filter, so the victim's agent is instructed to run the
// attacker-chosen probe (here: 169.254.169.254 — a cloud metadata endpoint).
func TestNetworkMonitorIDOR_ReachesVictimAgent_PoC(t *testing.T) {
	victimSys, app := newTestSystemWithHub(t)

	// The attacker-injected probe as it exists after the IDOR PATCH: it lives on
	// the victim's system and targets an address of the attacker's choosing.
	collection, err := app.FindCachedCollectionByNameOrId("network_monitors")
	require.NoError(t, err)
	probe := core.NewRecord(collection)
	probe.Load(map[string]any{
		"system": victimSys.Id, "target": "169.254.169.254", "protocol": "tcp",
		"port": 80, "interval": 60, "enabled": true,
	})
	require.NoError(t, app.SaveNoValidate(probe))

	// Bring the victim's agent online (mock agent that records what the hub sends).
	sm := NewSystemManager(stubHub{app})
	require.NoError(t, sm.createSSHClientConfig())
	t.Cleanup(func() {
		sm.cancel()
		_ = sm.RemoveSystem(victimSys.Id)
		sm.smartFetchMap.StopCleaner()
		sm.zfsFetchMap.StopCleaner()
	})
	version := semver.MustParse("0.20.0")
	connections := make(chan *ws.WsConn, 1)
	upgrader := gws.NewUpgrader(&monitorSyncServer{}, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		wsConn := ws.NewWsConnection(conn, version)
		conn.Session().Store("wsConn", wsConn)
		connections <- wsConn
		conn.ReadLoop()
	}))
	t.Cleanup(server.Close)

	client := &monitorSyncClient{requests: make(chan common.HubRequest[monitor.SyncRequest], 2)}
	conn, _, err := gws.NewClient(client, &gws.ClientOption{Addr: "ws" + strings.TrimPrefix(server.URL, "http")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.NetConn().Close() })
	go conn.ReadLoop()

	select {
	case wsConn := <-connections:
		require.NoError(t, sm.AddWebSocketSystem(victimSys.Id, version, wsConn))
	case <-time.After(3 * time.Second):
		t.Fatal("victim agent websocket connection was not established")
	}

	select {
	case req := <-client.requests:
		require.Equal(t, common.SyncNetworkMonitors, req.Action)
		found := false
		for _, cfg := range req.Data.Configs {
			if cfg.Target == "169.254.169.254" {
				found = true
			}
		}
		require.True(t, found,
			"victim's agent must have received the attacker-injected probe target")
		t.Logf(">>> IMPACT CONFIRMED: victim agent for system %s was instructed to probe %q (%s:%d) — an attacker-controlled target injected via the network_monitors IDOR",
			victimSys.Id, req.Data.Configs[0].Target, req.Data.Configs[0].Protocol, req.Data.Configs[0].Port)
	case <-time.After(3 * time.Second):
		t.Fatal("victim agent did not receive the injected monitor")
	}
}
