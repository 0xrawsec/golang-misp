package config

import (
	"dependencies/toolbox/utils/log"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
)

// Config : configuration structure definition
type Config map[string]Value

// Value : stored in the configuration
type Value interface{}

var (
	ErrNoSuchKey = errors.New("No such key")
)

// Loads : loads a configuration structure from a data buffer
// @data : buffer containing the configuration object
// return (Config, error) : the Config struct filled from data, error code
func Loads(data []byte) (c Config, err error) {
	err = json.Unmarshal(data, &c)
	if err != nil {
		return
	}
	return
}

// Load : loads a configuration structure from a file
// @path : path where the configuration is stored as a json file
// return (Config, error) : the Config struct parsed, error code
func Load(path string) (c Config, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	return Loads([]byte(data))
}

// Dumps : Dumps Config structure into a byte slice
// return ([]byte, error) : byte slice and error code
func (c *Config) Dumps() (dump []byte, err error) {
	dump, err = json.Marshal(c)
	if err != nil {
		return
	}
	return
}

// Debug : prints out the configuration in debug information
func (c *Config) Debug() {
	for key, val := range *c {
		log.Debugf("config[%s] = %v", key, val)
	}
}

// Get : get the Value associated to a key found in Config structure
// return (Value, error) : Value associated to key and error code
func (c *Config) Get(key string) (Value, error) {
	val, ok := (*c)[key]
	if !ok {
		return val, ErrNoSuchKey
	}
	return val, nil
}

func (c *Config) GetString(key string) (string, error) {
	val, ok := (*c)[key]
	if !ok {
		return "", ErrNoSuchKey
	}
	return val.(string), nil
}

// GetRequired : get the Value associated to a key found in Config structure and exit if
// not available
// return (Value) : Value associated to key if it exists
func (c *Config) GetRequired(key string) Value {
	val, err := c.Get(key)
	if err != nil {
		log.Errorf("Configuration parameter %s is mandatory", key)
		os.Exit(1)
	}
	return val
}

func (c *Config) GetRequiredString(key string) string {
	return c.GetRequired(key).(string)
}

func (c *Config) GetRequiredInt64(key string) int64 {
	val := c.GetRequired(key)
	switch val.(type) {
	case int64:
		return val.(int64)
	default:
		// json loads float64 so handle that case
		return int64(val.(float64))
	}
}

func (c *Config) GetRequiredUint64(key string) uint64 {
	val := c.GetRequired(key)
	switch val.(type) {
	case uint64:
		return val.(uint64)
	default:
		// json loads float64 so handle that case
		return uint64(val.(float64))
	}
}

// Set : set parameter identified by key of the Config struct with a Value
func (c *Config) Set(key string, value interface{}) {
	(*c)[key] = value
}
