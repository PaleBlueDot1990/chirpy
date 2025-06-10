package auth

import (
	"fmt"
	"net/http"
	"strings"
)

func GetPolkaApiKey(headers http.Header) (string, error) {
	token := headers.Get("Authorization")
	if token == "" {
		return "", fmt.Errorf("bearer token is missing")
	}

	token = strings.TrimSpace(token)
	return token[7:], nil	
}