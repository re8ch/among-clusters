package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
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
	go handleExport(server, map[string]string{"spiffe://remote/ns/default/service/api": upstream.Addr().String()})
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
