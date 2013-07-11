// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"strings"
	"testing"
)

var testCookies = []interface{}{
	map[string]string{"foo": "bar"},
	map[string]string{"baz": "ding"},
}

var testStrings = []string{"foo", "bar", "baz"}

func TestSecureCookie(t *testing.T) {
	s1 := New([]byte("12345"), []byte("1234567890123456"))
	s2 := New([]byte("54321"), []byte("6543210987654321"))
	value := []byte("foobar")

	for i := 0; i < 50; i++ {
		// Running this multiple times to check if any special character
		// breaks encoding/decoding.
		encoded, err1 := s1.Encode("sid", value)
		if err1 != nil {
			t.Error(err1)
			continue
		}
		v, ts, err2 := s1.Decode("sid", encoded)
		if err2 != nil {
			t.Fatalf("%v: %v", err2, encoded)
		}
		if string(v) != string(value) {
			t.Fatalf("Expected %v, got %v.", string(value), string(v))
		}
		if ts.IsZero() {
			t.Fatalf("Expected time")
		}
		_, _, err3 := s2.Decode("sid", encoded)
		if err3 == nil {
			t.Fatalf("Expected failure decoding.")
		}
	}
}

func TestMultiError(t *testing.T) {
	s1, s2 := New(nil, nil), New(nil, nil)
	_, err := EncodeMulti("sid", []byte("value"), s1, s2)
	if len(err.(MultiError)) != 2 {
		t.Errorf("Expected 2 errors, got %s.", err)
	} else {
		if strings.Index(err.Error(), "hash key is not set") == -1 {
			t.Errorf("Expected missing hash key error, got %s.", err.Error())
		}
	}
}
