package miu

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func pendingPacketDial(t *testing.T) (net.PacketConn, <-chan error) {
	t.Helper()
	started := make(chan struct{}, 1)
	client, err := NewClient(ClientConfig{
		PSK: "0123456789abcdef",
		Dial: func(ctx context.Context) (net.Conn, error) {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	pc, err := client.ListenPacket()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	result := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo([]byte("test"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("initial UDP dial did not start")
	}
	return pc, result
}

func TestPacketCloseCancelsInitialDial(t *testing.T) {
	pc, result := pendingPacketDial(t)
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not cancel initial UDP dial")
	}
}

func TestPacketWriteDeadlineCancelsInitialDial(t *testing.T) {
	pc, result := pendingPacketDial(t)
	if err := pc.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write deadline: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write deadline did not cancel initial UDP dial")
	}
}

func TestPacketWriteDeadlineCanBeExtendedWhileDialing(t *testing.T) {
	pc, result := pendingPacketDial(t)
	if err := pc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		t.Fatalf("extended deadline canceled dial early: %v", err)
	case <-time.After(650 * time.Millisecond):
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not cancel initial UDP dial")
	}
}
