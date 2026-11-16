package encryption

import (
	"errors"
	"fmt"
	"testing"
)

func TestDecodeHeaderLimits(t *testing.T) {
	for _, length := range []int{0, 16, 17, 8208, 16640, 16641, 17000, 65535} {
		t.Run(fmt.Sprintf("length=%d", length), func(t *testing.T) {
			header := make([]byte, 5)
			EncodeHeader(header, length)
			got, err := DecodeHeader(header)
			if got != length {
				t.Fatalf("decoded length = %d, want %d", got, length)
			}
			wantError := length < 17 || length > 16640
			if (err != nil) != wantError {
				t.Fatalf("DecodeHeader() error = %v, want error %v", err, wantError)
			}
			if wantError && !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("error does not preserve ErrInvalidHeader: %v", err)
			}
		})
	}
}

func TestDecodeHeaderInvalidType(t *testing.T) {
	for _, index := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("byte=%d", index), func(t *testing.T) {
			header := make([]byte, 5)
			EncodeHeader(header, 17)
			header[index] ^= 1
			length, err := DecodeHeader(header)
			if length != 0 || !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("DecodeHeader() = %d, %v, want 0, ErrInvalidHeader", length, err)
			}
		})
	}
}
