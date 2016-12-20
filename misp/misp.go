package misp

import (
	"bytes"
	"crypto/tls"
	"dependencies/toolbox/config"
	"dependencies/toolbox/utils/log"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"
)

type MispError struct {
	StatusCode int
	Message    string
}

func (me MispError) Error() string {
	return fmt.Sprintf("MISP ERROR (HTTP %d) : %s", me.StatusCode, me.Message)
}

type MispCon struct {
	Proto      string
	Host       string
	APIKey     string
	RestAPIURL string
	Client     *http.Client
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
	Value           string `json:"value"`
	Type            string `json:"type"`
	Category        string `json:"category"`
	Org             string `json:"org"`
	Tags            string `json:"tags"`
	QuickFilter     string `json:"quickfilter"`
	From            string `json:"from"`
	To              string `json:"to"`
	Last            string `json:"last"`
	EventID         string `json:"eventid"`
	WithAttachments string `json:"withAttachments"`
	Metadata        string `json:"metadata"`
	SearchAll       int8   `json:"searchall"`
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
	ID                 string             `json:"id"`
	OrgcID             string             `json:"orgc_id"`
	OrgID              string             `json:"org_id"`
	Date               string             `json:"date"`
	ThreatLevelID      string             `json:"threat_level_id"`
	Info               string             `json:"info"`
	Published          bool               `json:"published"`
	UUID               string             `json:"uuid"`
	AttributeCount     string             `json:"attribute_count"`
	Analysis           string             `json:"analysis"`
	StrTimestamp       string             `json:"timestamp"`
	Distribution       string             `json:"distribution"`
	ProposalEmailLock  bool               `json:"proposal_email_lock"`
	Locked             bool               `json:"locked"`
	PublishedTimestamp string             `json:"publish_timestamp"`
	SharingGroupID     string             `json:"sharing_group_id"`
	Org                Org                `json:"Org"`
	Orgc               Org                `json:"Orgc"`
	Attribute          []MispAttribute    `json:"Attribute"`
	ShadowAttribute    []MispAttribute    `json:"ShadowAttribute"`
	RelatedEvent       []MispRelatedEvent `json:"RelatedEvent"`
	Galaxy             []MispRelatedEvent `json:"Galaxy"`
}

// Timestamp : return Time struct according to a string time
func (me MispEvent) Timestamp() time.Time {
	sec, err := strconv.ParseInt(me.StrTimestamp, 10, 64)
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
	Value    string `json:"value"`
	Type     string `json:"type"`
	Category string `json:"category"`
	Org      string `json:"org"`
	Tags     string `json:"tags"`
	From     string `json:"from"`
	To       string `json:"to"`
	Last     string `json:"last"`
	EventID  string `json:"eventid"`
	UUID     string `json:"uuid"`
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
	APIURL string
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// MISP Interface //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

var (
	// ErrUnknownProtocol : raised when bad protocol specified
	ErrUnknownProtocol = errors.New("Unknown protocol")
)

func logRequest(req *http.Request) {
	proxyURL, err := http.ProxyFromEnvironment(req)
	if err != nil {
		panic(err)
	}
	log.Infof("Proxy: %s", proxyURL.String())
	log.Infof("%s - %s %s", req.RemoteAddr, req.Method, req.URL)
	log.Infof("Header: %s", req.Header)
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
	mc.APIURL = conf.GetRequiredString("api-url")
	return
}

// NewInsecureCon : Return a new MispCon with insecured TLS connection settings
// return (MispCon)
func NewInsecureCon(proto, host, apiKey, restApiUrl string) MispCon {
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
	return MispCon{proto, host, apiKey, restApiUrl, &c}
}

// NewCon : create a new MispCon struct
// return (MispcCon)
func NewCon(proto, host, apiKey, restApiUrl string) MispCon {
	if proto != "http" && proto != "https" {
		log.Errorf("%s : only http and https protocols are allowed", ErrUnknownProtocol.Error())
		panic(ErrUnknownProtocol)
	}
	return MispCon{proto, host, apiKey, restApiUrl, &http.Client{}}
}

func (mc MispCon) postSearch(kind string, mq *MispQuery) ([]byte, error) {
	fullURL := fmt.Sprintf("%s://%s/%s%s", mc.Proto, mc.Host, kind, mc.RestAPIURL)
	pReq, err := http.NewRequest("POST", fullURL, bytes.NewReader((*mq).Prepare()))
	if err != nil {
		return []byte{}, err
	}
	pReq.Header.Add("Authorization", mc.APIKey)
	pReq.Header.Add("Content-Type", "application/json")
	pReq.Header.Add("Accept", "application/json")
	logRequest(pReq)
	if err != nil {
		return []byte{}, err
	}
	pResp, err := mc.Client.Do(pReq)
	if err != nil {
		return []byte{}, err
	}
	defer pResp.Body.Close()

	respBody, err := ioutil.ReadAll(pResp.Body)
	if err != nil {
		panic(err)
	}
	switch pResp.StatusCode {
	case 200:
		return respBody, err
	default:
		return []byte{}, MispError{pResp.StatusCode, string(respBody)}
	}
}

// Search : Issue a search and return a MispObject
// @mq : a struct implementing MispQuery interface
// return (MispObject)
func (mc MispCon) Search(mq MispQuery) MispResponse {
	switch mq.(type) {
	case MispAttributeQuery:
		mar := MispAttributeResponse{}
		bResp, err := mc.postSearch("attributes", &mq)
		if err != nil {
			log.Error(err)
			break
		}
		err = json.Unmarshal(bResp, &mar)
		if err != nil {
			panic(err)
		}
		return mar

	case MispEventQuery:
		mer := MispEventResponse{}
		bResp, err := mc.postSearch("events", &mq)
		if err != nil {
			log.Error(err)
			break
		}
		err = json.Unmarshal(bResp, &mer)
		if err != nil {
			panic(err)
		}
		return mer
	}
	return EmptyMispResponse{}
}
