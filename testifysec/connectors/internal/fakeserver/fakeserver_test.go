package fakeserver

import (
	"io"
	"net/http"
	"testing"
)

func TestResponseSequence(t *testing.T) {
	s := New(t, "", Route{Method: "GET", Path: "/job", Responses: []Response{
		{Status: 202, Body: "pending"}, {Body: "running", Header: map[string]string{"X-Next-Page": "2"}}, {Body: "done"},
	}})
	var got []string
	for range 4 {
		r, err := http.Get(s.URL + "/job")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		got = append(got, r.Status[:3]+" "+string(b)+" "+r.Header.Get("X-Next-Page"))
	}
	want := []string{"202 pending ", "200 running 2", "200 done ", "200 done "}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d: %q, want %q", i, got[i], want[i])
		}
	}
	if len(s.Requests()) != 4 {
		t.Errorf("recorded %d requests", len(s.Requests()))
	}
}
