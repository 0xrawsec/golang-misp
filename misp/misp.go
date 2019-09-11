package misp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xrawsec/golang-utils/config"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/readers"
)

type MispError struct {
	StatusCode int
	Message    string
}

func (me MispError) Error() string {
	return fmt.Sprintf("MISP ERROR (HTTP %d) : %s", me.StatusCode, me.Message)
}

type MispCon struct {
	Proto  string
	Host   string
	APIKey string
	Client *http.Client
}

type MispRequest struct {
	Request MispQuery `json:"request"`
}

type MispQuery interface {
	// Prepare the query and returns a JSON object in a form of a byte array
	Prepare() []byte
}

type MispObject interface{}

type MispResponse interface {
	Iter() chan MispObject
}

type EmptyMispResponse struct{}

// Iter : MispResponse implementation
func (emr EmptyMispResponse) Iter() chan MispObject {
	c := make(chan MispObject)
	close(c)
	return c
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// Events //////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// MispEventQuery : defines the structure of query to event search API
type MispEventQuery struct {
	Value           string `json:"value,omitempty"`
	Type            string `json:"type,omitempty"`
	Category        string `json:"category,omitempty"`
	Org             string `json:"org,omitempty"`
	Tags            string `json:"tags,omitempty"`
	QuickFilter     string `json:"quickfilter,omitempty"`
	From            string `json:"from,omitempty"`
	To              string `json:"to,omitempty"`
	Last            string `json:"last,omitempty"`
	EventID         string `json:"eventid,omitempty"`
	WithAttachments string `json:"withAttachments,omitempty"`
	Metadata        string `json:"metadata,omitempty"`
	SearchAll       int8   `json:"searchall,omitempty"`
}

// Prepare : MispQuery Implementation
func (meq MispEventQuery) Prepare() (j []byte) {
	jsMeq, err := json.Marshal(MispRequest{meq})
	if err != nil {
		panic(err)
	}
	return jsMeq
}

// Org definition
type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// MispRelatedEvent definition
type MispRelatedEvent struct {
	ID            string `json:"id"`
	Date          string `json:"date"`
	ThreatLevelID string `json:"threat_level_id"`
	Info          string `json:"info"`
	Published     bool   `json:"published"`
	UUID          string `json:"uuid"`
	Analysis      string `json:"analysis"`
	StrTimestamp  string `json:"timestamp"`
	Distribution  string `json:"distribution"`
	OrgID         string `json:"org_id"`
	OrgcID        string `json:"orgc_id"`
	Org           Org    `json:"Org"`
	Orgc          Org    `json:"Orgc"`
}

// Timestamp : return Time struct according to a string time
func (mre *MispRelatedEvent) Timestamp() time.Time {
	sec, err := strconv.ParseInt(mre.StrTimestamp, 10, 64)
	if err != nil {
		panic(err)
	}
	return time.Unix(sec, 0)
}

// MispEvent definition
type MispEvent struct {
	ID                    string             `json:"id"`
	OrgcID                string             `json:"orgc_id"`
	OrgID                 string             `json:"org_id"`
	Date                  string             `json:"date"`
	ThreatLevelID         string             `json:"threat_level_id"`
	Info                  string             `json:"info"`
	Published             bool               `json:"published"`
	UUID                  string             `json:"uuid"`
	AttributeCount        string             `json:"attribute_count"`
	Analysis              string             `json:"analysis"`
	StrTimestamp          string             `json:"timestamp"`
	Distribution          string             `json:"distribution"`
	ProposalEmailLock     bool               `json:"proposal_email_lock"`
	Locked                bool               `json:"locked"`
	StrPublishedTimestamp string             `json:"publish_timestamp"`
	SharingGroupID        string             `json:"sharing_group_id"`
	Org                   Org                `json:"Org"`
	Orgc                  Org                `json:"Orgc"`
	Attribute             []MispAttribute    `json:"Attribute"`
	ShadowAttribute       []MispAttribute    `json:"ShadowAttribute"`
	RelatedEvent          []MispRelatedEvent `json:"RelatedEvent"`
	Galaxy                []MispRelatedEvent `json:"Galaxy"`
}

// Timestamp : return Time struct according to a string time
func (me MispEvent) Timestamp() time.Time {
	sec, err := strconv.ParseInt(me.StrTimestamp, 10, 64)
	if err != nil {
		panic(err)
	}
	return time.Unix(sec, 0)
}

// PublishedTimestamp : return Time struct according to a string time
func (me MispEvent) PublishedTimestamp() time.Time {
	sec, err := strconv.ParseInt(me.StrPublishedTimestamp, 10, 64)
	if err != nil {
		panic(err)
	}
	return time.Unix(sec, 0)
}

// MispEventDict : intermediate structure to handle properly MISP API results
type MispEventDict struct {
	Event MispEvent `json:"Event"`
}

// MispEventResponse : intermediate structure to handle properly MISP API results
type MispEventResponse struct {
	Response []MispEventDict `json:"response"`
}

// Iter : MispResponse implementation
func (mer MispEventResponse) Iter() (moc chan MispObject) {
	moc = make(chan MispObject)
	go func() {
		defer close(moc)
		for _, me := range mer.Response {
			moc <- me.Event
		}
	}()
	return
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// Attributes ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

type MispAttributeQuery struct {
	Value    string `json:"value,omitempty"`
	Type     string `json:"type,omitempty"`
	Category string `json:"category,omitempty"`
	Org      string `json:"org,omitempty"`
	Tags     string `json:"tags,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Last     string `json:"last,omitempty"`
	EventID  string `json:"eventid,omitempty"`
	UUID     string `json:"uuid,omitempty"`
}

// Prepare : MispQuery Implementation
func (maq MispAttributeQuery) Prepare() (j []byte) {
	jsMaq, err := json.Marshal(MispRequest{maq})
	if err != nil {
		panic(err)
	}
	return jsMaq
}

// MispAttributeDict : itermediate structure to handle MISP attribute search
type MispAttributeDict struct {
	Attribute []MispAttribute `json:"Attribute"`
}

// MispAttributeResponse : API response when attribute query is done
type MispAttributeResponse struct {
	Response MispAttributeDict `json:"response"`
}

// Iter : MispResponse implementation
func (mar MispAttributeResponse) Iter() (moc chan MispObject) {
	moc = make(chan MispObject)
	go func() {
		defer close(moc)
		for _, ma := range mar.Response.Attribute {
			moc <- ma
		}
	}()
	return
}

// MispAttribute : define structure of attribute object returned by API
type MispAttribute struct {
	ID             string `json:"id"`
	EventID        string `json:"event_id"`
	UUID           string `json:"uuid"`
	SharingGroupID string `json:"sharing_group_id"`
	StrTimestamp   string `json:"timestamp"`
	Distribution   string `json:"distribution"`
	Category       string `json:"category"`
	Type           string `json:"type"`
	Value          string `json:"value"`
	ToIDS          bool   `json:"to_ids"`
	Deleted        bool   `json:"deleted"`
	Comment        string `json:"comment"`
}

// Timestamp : return Time struct according to a string time
func (ma MispAttribute) Timestamp() time.Time {
	sec, err := strconv.ParseInt(ma.StrTimestamp, 10, 64)
	if err != nil {
		panic(err)
	}
	return time.Unix(sec, 0)
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// Config ////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// MispConfig structure
type MispConfig struct {
	Proto  string
	Host   string
	APIKey string
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// MISP Interface //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

var (
	// ErrUnknownProtocol : raised when bad protocol specified
	ErrUnknownProtocol = errors.New("Unknown protocol")
)

func headerSortedKeys(d http.Header) (sk []string) {
	sk = make([]string, 0, len(d))
	for k := range d {
		sk = append(sk, k)
	}
	sort.Strings(sk)
	return
}

func logRequest(req *http.Request) {
	proxyURL, err := http.ProxyFromEnvironment(req)
	if err != nil {
		panic(err)
	}
	body, _ := req.GetBody()
	log.Debugf("Proxy: %s", proxyURL)
	log.Debugf("%s %s", req.Method, req.URL)
	log.Debug("Header:")
	for _, sk := range headerSortedKeys(req.Header) {
		for _, v := range req.Header[sk] {
			log.Debugf("        %s: %v", sk, v)
		}
	}
	log.Debugf("Body: %s", string(readAllOrPanic(body)))
}

func readAllOrPanic(r io.Reader) []byte {
	respBody, err := ioutil.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return respBody
}

// LoadConfig : load a configuration file from path
// return (MispConfig)
func LoadConfig(path string) (mc MispConfig) {
	conf, err := config.Load(path)
	if err != nil {
		panic(err)
	}
	mc.Proto = conf.GetRequiredString("protocol")
	mc.Host = conf.GetRequiredString("host")
	mc.APIKey = conf.GetRequiredString("api-key")
	return
}

// NewInsecureCon : Return a new MispCon with insecured TLS connection settings
// return (MispCon)
func NewInsecureCon(proto, host, apiKey string) MispCon {
	if proto != "http" && proto != "https" {
		log.Errorf("%s : only http and https protocols are allowed", ErrUnknownProtocol.Error())
		panic(ErrUnknownProtocol)
	}
	var noCertTransport http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	c := http.Client{Transport: noCertTransport}
	return MispCon{proto, host, apiKey, &c}
}

// NewCon : create a new MispCon struct
// return (MispcCon)
func NewCon(proto, host, apiKey string) MispCon {
	if proto != "http" && proto != "https" {
		log.Errorf("%s : only http and https protocols are allowed", ErrUnknownProtocol.Error())
		panic(ErrUnknownProtocol)
	}
	return MispCon{proto, host, apiKey, &http.Client{}}
}

func (mc MispCon) buildURL(path ...string) string {
	for i := range path {
		path[i] = strings.TrimLeft(path[i], "/")
	}
	return fmt.Sprintf("%s://%s/%s", mc.Proto, mc.Host, strings.Join(path, "/"))
}

func (mc MispCon) prepareRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	req.Header.Add("Authorization", mc.APIKey)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", fmt.Sprintf("GolangMisp/%s (https://github.com/0xrawsec/golang-misp)", version))
	return req, err
}

func (mc MispCon) postSearch(kind string, mq *MispQuery) ([]byte, error) {
	fullURL := mc.buildURL(kind, "restSearch", "download")
	pReq, err := mc.prepareRequest("POST", fullURL, bytes.NewReader((*mq).Prepare()))
	if err != nil {
		return []byte{}, err
	}
	if err != nil {
		return []byte{}, err
	}
	logRequest(pReq)
	pResp, err := mc.Client.Do(pReq)
	if err != nil {
		return []byte{}, err
	}
	defer pResp.Body.Close()

	respBody := readAllOrPanic(pResp.Body)
	switch pResp.StatusCode {
	case 200:
		return respBody, err
	default:
		return []byte{}, MispError{pResp.StatusCode, string(respBody)}
	}
}

// Search : Issue a search and return a MispObject
// @mq : a struct implementing MispQuery interface
// return (MispObject, error)
func (mc MispCon) Search(mq MispQuery) (MispResponse, error) {
	switch mq.(type) {
	case MispAttributeQuery:
		mar := MispAttributeResponse{}
		bResp, err := mc.postSearch("attributes", &mq)
		if err != nil {
			log.Debugf("Error: %s", err)
			return EmptyMispResponse{}, err
		}
		err = json.Unmarshal(bResp, &mar)
		if err != nil {
			log.Debug(string(bResp))
			return mar, err
		}
		return mar, nil

	case MispEventQuery:
		mer := MispEventResponse{}
		bResp, err := mc.postSearch("events", &mq)
		if err != nil {
			log.Debugf("Error: %s", err)
			return EmptyMispResponse{}, err
		}
		err = json.Unmarshal(bResp, &mer)
		if err != nil {
			log.Debug(string(bResp))
			return mer, err
		}
		return mer, nil
	}
	return EmptyMispResponse{}, fmt.Errorf("Empty Response")
}

// TextExport text export API wrapper https://<misp url>/attributes/text/download/
// The wrapper takes care of removing the duplicated entries
// @flags: the list of flags to use for the query
func (mc MispCon) TextExport(flags ...string) (out []string, err error) {
	path := make([]string, 0)
	path = append(path, "attributes", "text", "download")
	path = append(path, flags...)

	url := mc.buildURL(path...)

	out = make([]string, 0)

	pReq, err := mc.prepareRequest("GET", url, new(bytes.Buffer))
	if err != nil {
		return
	}
	logRequest(pReq)
	pResp, err := mc.Client.Do(pReq)
	if err != nil {
		return
	}
	defer pResp.Body.Close()
	switch pResp.StatusCode {
	case 200:
		// used to remove duplicates
		marked := datastructs.NewSyncedSet()
		for line := range readers.Readlines(pResp.Body) {
			txt := string(line)
			if !marked.Contains(txt) {
				out = append(out, txt)
			}
			marked.Add(txt)
		}
	default:
		return out, MispError{pResp.StatusCode, string(readAllOrPanic(pResp.Body))}
	}
	return
}
