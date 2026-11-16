package miu

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type notifiedWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *notifiedWriteConn) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(b)
}

func blockedAuthClient(t *testing.T) (*Client, <-chan struct{}) {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = conn.Close() })
	notified := &notifiedWriteConn{Conn: conn, started: make(chan struct{})}
	client, err := NewClient(ClientConfig{
		PSK: "0123456789abcdef",
		Dial: func(context.Context) (net.Conn, error) {
			return notified, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, notified.started
}

func waitForAuthWrite(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("authentication write did not start")
	}
}

func TestDialCancellationUnblocksAuthenticationWrite(t *testing.T) {
	client, started := blockedAuthClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(ctx, "tcp", "example.com:443")
		if err == nil && conn != nil {
			_ = conn.Close()
		}
		if err != nil && conn != nil {
			result <- errors.New("failed dial returned a non-nil connection")
			return
		}
		result <- err
	}()
	waitForAuthWrite(t, started)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled authentication returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not unblock authentication write")
	}
}

func TestAuthenticationStopsWatchingContextAfterWrite(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	l := newLane(conn, false, false)
	received := make(chan error, 1)
	go func() {
		buf := make([]byte, 2)
		_, err := peer.Read(buf[:1])
		if err == nil {
			_, err = peer.Read(buf[1:])
		}
		received <- err
	}()
	ctx, cancel := context.WithCancel(context.Background())
	if err := writeAuth(ctx, l, []byte{1}); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte{2}); err != nil {
		t.Fatalf("cancel after authentication closed the connection: %v", err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
}

func TestPacketStopUnblocksAuthenticationWrite(t *testing.T) {
	for _, mode := range []string{"close", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			client, started := blockedAuthClient(t)
			pc, err := client.ListenPacket()
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			result := make(chan error, 1)
			go func() {
				_, err := pc.WriteTo([]byte("test"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
				result <- err
			}()
			waitForAuthWrite(t, started)
			want := error(net.ErrClosed)
			if mode == "close" {
				err = pc.Close()
			} else {
				want = os.ErrDeadlineExceeded
				err = pc.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("%s during authentication returned %v", mode, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("%s did not unblock authentication write", mode)
			}
		})
	}
}
