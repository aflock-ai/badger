// jade:ring local
package main

import (
	"context"
	"io"
	"os"
	"testing"
	"time"
)

func TestOwnedInputCancellation(t *testing.T) {
	for _, partial := range []string{"", "{\"payload\":"} {
		t.Run(partial, func(t *testing.T) {
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer writer.Close()
			if partial != "" {
				if _, err = writer.Write([]byte(partial)); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			finish := closeInputOnCancel(ctx, input)
			defer finish()
			start := time.Now()
			_, err = io.ReadAll(input)
			if err == nil || time.Since(start) > time.Second {
				t.Fatal("owned input did not cancel", err)
			}
		})
	}
}
