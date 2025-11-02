package main

import (
	"regexp"
	"strings"
)

type Config struct {
	Port      int    `yaml:"port"`
	Interface string `yaml:"interface"`
	Ttl       int    `yaml:"ttl"`
}

func LoadConfig(path string) (config *Config, err error) {

	return
}

func IsFakeStrategy(targetHost string) (ok bool, replace string) {
	replace = targetHost
	list := []string{".*\\.ytimg", ".*youtube\\.com", ".*\\.vpnc\\.ru", "vpnc\\.ru", "flibusta\\.is"}

	for _, str := range list {
		if ok, _ := regexp.Match(str, []byte(targetHost)); ok {
			if strings.Contains(replace, "youtube") {
				replace = strings.Replace(replace, "youtube", "tubelog", -1)
			} else {
				replace = replace[:len(replace)-1] + "x"
			}
			return true, replace
		}
	}

	return false, replace
}
