package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestExportTunnelRoutesByServiceIdentity(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		connection, _ := upstream.Accept()
		if connection != nil {
			defer connection.Close()
			io.Copy(connection, connection)
		}
	}()
	client, server := net.Pipe()
	defer client.Close()
	routes := map[string]exportRoute{"spiffe://remote/ns/default/service/api": {ServiceIdentity: "spiffe://remote/ns/default/service/api", Target: upstream.Addr().String(), TargetPeers: []string{"remote-local"}}}
	identities := map[string][]string{"remote-local": {"spiffe://caller.test/cluster/caller"}}
	go handleExport(server, routes, identities, "spiffe://caller.test/cluster/caller")
	identity := []byte("spiffe://remote/ns/default/service/api")
	if err = binary.Write(client, binary.BigEndian, uint16(len(identity))); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write(identity); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	result := make([]byte, 4)
	if _, err = io.ReadFull(client, result); err != nil {
		t.Fatal(err)
	}
	if string(result) != "ping" {
		t.Fatalf("got %q", result)
	}
}

func TestExportAcknowledgesSessionHeartbeat(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go handleExport(server, nil, nil, "spiffe://caller.test/cluster/caller")
	identity := []byte(sessionHeartbeatIdentity)
	if err := binary.Write(client, binary.BigEndian, uint16(len(identity))); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(identity); err != nil {
		t.Fatal(err)
	}
	ack := []byte{0}
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatal(err)
	}
	if ack[0] != 1 {
		t.Fatalf("unexpected heartbeat acknowledgement %d", ack[0])
	}
}

func TestSessionRegistryKeepsLongLivedSessionWhenProbeCloses(t *testing.T) {
	registry := newSessionRegistry()
	first := new(quic.Conn)
	second := new(quic.Conn)
	registry.put("spiffe://remote.test/cluster/remote/", first)
	if !registry.has("spiffe://remote.test/cluster/remote") {
		t.Fatal("active persistent session was not ready")
	}
	if got := registry.get("spiffe://remote.test/cluster/remote"); got != first {
		t.Fatal("canonical SPIFFE identity did not resolve the registered session")
	}
	registry.put("spiffe://remote.test/cluster/remote", second)
	registry.remove("spiffe://remote.test/cluster/remote", second)
	if got := registry.get("spiffe://remote.test/cluster/remote"); got != first {
		t.Fatal("a closing probe removed the long-lived peer session")
	}
	registry.remove("spiffe://remote.test/cluster/remote", first)
	if registry.has("spiffe://remote.test/cluster/remote") {
		t.Fatal("closed session remained ready")
	}
	if got := registry.get("spiffe://remote.test/cluster/remote"); got != nil {
		t.Fatal("closed current session remained registered")
	}
}

func TestExportRouteDeniesIdentityOutsideTargetPeer(t *testing.T) {
	route := exportRoute{ServiceIdentity: "spiffe://remote/ns/default/service/api", TargetPeers: []string{"remote-local"}}
	identities := map[string][]string{"remote-local": {"spiffe://allowed.test/cluster/allowed"}}
	if routeAllowsIdentity(route, identities, "spiffe://other.test/cluster/other") {
		t.Fatal("service route allowed a SPIFFE identity outside its target peer")
	}
	if !routeAllowsIdentity(route, identities, "spiffe://allowed.test/cluster/allowed") {
		t.Fatal("service route denied its explicitly configured target peer")
	}
}
