package main

import (
	"misp"
	"testing"

	"github.com/0xrawsec/golang-utils/log"
)

var (
	proto  = ""
	host   = ""
	key    = ""
	apiURL = ""
)

func init() {
	log.InitLogger(log.LDebug)
	mc := misp.LoadConfig("./config.json")
	proto = mc.Proto
	host = mc.Host
	key = mc.APIKey
	apiURL = mc.APIURL
}

func TestSimpleAttributeSearch(t *testing.T) {
	con := misp.NewInsecureCon(proto, host, key, apiURL)
	ma := misp.MispAttributeQuery{Last: "1d"}
	t.Log(con.Search(ma))
	for a := range con.Search(ma).Iter() {
		t.Log(a.(misp.MispAttribute).Timestamp())
		t.Log(a)
	}
}

func TestSimpleEventSearch(t *testing.T) {
	con := misp.NewInsecureCon(proto, host, key, apiURL)
	//me := misp.MispEventQuery{Value: "red october", SearchAll: 1, EventID: "15"}
	me := misp.MispEventQuery{Last: "1d"}
	for e := range con.Search(me).Iter() {
		t.Log(e.(misp.MispEvent).Timestamp())
		t.Log(e)
	}
}
