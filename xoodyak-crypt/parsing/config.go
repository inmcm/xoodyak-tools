package parsing

import (
	"encoding/json"
	"fmt"
	"os"
)

type Configuration struct {
	Key      string `json:"key"`
	Nonce    string `json:"nonce"`
	Metadata string `json:"ad,omitempty"`
}

func ReadConfig(file string, mustExist bool) (cfg *Configuration, err error) {
	cfg = &Configuration{}
	if _, err = os.Stat(file); err != nil {
		if mustExist {
			err = fmt.Errorf("xoodyak config file err: %w", err)
		} else {
			err = nil
		}
		return
	}

	cfgBytes, err := os.ReadFile(file)
	if err != nil {

		return
	}
	err = json.Unmarshal(cfgBytes, cfg)
	return
}

func SaveConfig(cfg *Configuration, file string) (err error) {
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	err = os.WriteFile(file, cfgBytes, 0644)
	return
}
