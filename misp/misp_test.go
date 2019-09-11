package misp

import (
	"testing"

	"github.com/0xrawsec/golang-utils/log"
)

var (
	proto = ""
	host  = ""
	key   = ""
)

func init() {
	log.InitLogger(log.LDebug)
	mc := LoadConfig("./test/config.json")
	proto = mc.Proto
	host = mc.Host
	key = mc.APIKey
}

func TestSimpleAttributeSearch(t *testing.T) {
	con := NewInsecureCon(proto, host, key)
	ma := MispAttributeQuery{Last: "1d"}
	for a := range con.Search(ma).Iter() {
		t.Log(a.(MispAttribute).Timestamp())
		t.Log(a)
	}
}

func TestSimpleEventSearch(t *testing.T) {
	con := NewInsecureCon(proto, host, key)
	me := MispEventQuery{Last: "1d"}
	for e := range con.Search(me).Iter() {
		t.Log(e.(MispEvent).Timestamp())
		t.Log(e)
	}
}

func TestTextExport(t *testing.T) {
	con := NewInsecureCon(proto, host, key)
	domains, err := con.TextExport("mutex")
	if err != nil {
		t.Errorf("Failed TextExport: %s", err)
		t.FailNow()
	}
	for _, domain := range domains {
		t.Log(domain)
	}

}
