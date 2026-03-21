package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TURNCreds holds TURN server credentials.
type TURNCreds struct {
	Username string
	Password string
	Address  string // host:port
}

// GetVKCreds fetches TURN credentials from VK using a call invite link ID.
func GetVKCreds(linkID string) (*TURNCreds, error) {
	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		}
		defer client.CloseIdleConnections()
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}
		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, fmt.Errorf("unmarshal error: %w, body: %s", err, string(body))
		}
		return resp, nil
	}

	extractStr := func(resp map[string]interface{}, keys ...string) (string, error) {
		var cur interface{} = resp
		for _, k := range keys {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("expected map at key %q, got %T", k, cur)
			}
			cur = m[k]
		}
		s, ok := cur.(string)
		if !ok {
			return "", fmt.Errorf("expected string at end of path, got %T", cur)
		}
		return s, nil
	}

	// Step 1: get anonymous token
	data := "client_secret=QbYic1K3lEV5kTGiqlq2&client_id=6287487&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=6287487"
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("step1: %w", err)
	}
	token1, err := extractStr(resp, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("step1 parse: %w", err)
	}

	// Step 2: get anonymous access token payload
	data = fmt.Sprintf("access_token=%s", token1)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=6287487")
	if err != nil {
		return nil, fmt.Errorf("step2: %w", err)
	}
	token2, err := extractStr(resp, "response", "payload")
	if err != nil {
		return nil, fmt.Errorf("step2 parse: %w", err)
	}

	// Step 3: get messages token
	data = fmt.Sprintf("client_id=6287487&token_type=messages&payload=%s&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487", token2)
	resp, err = doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("step3: %w", err)
	}
	token3, err := extractStr(resp, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("step3 parse: %w", err)
	}

	// Step 4: get anonymous call token
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", linkID, token3)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264")
	if err != nil {
		return nil, fmt.Errorf("step4: %w", err)
	}
	token4, err := extractStr(resp, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("step4 parse: %w", err)
	}

	// Step 5: OK.ru anonymous login
	data = fmt.Sprintf("session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22%s%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", uuid.New())
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("step5: %w", err)
	}
	token5, err := extractStr(resp, "session_key")
	if err != nil {
		return nil, fmt.Errorf("step5 parse: %w", err)
	}

	// Step 6: join conversation and get TURN creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", linkID, token4, token5)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("step6: %w", err)
	}

	user, err := extractStr(resp, "turn_server", "username")
	if err != nil {
		return nil, fmt.Errorf("step6 parse username: %w", err)
	}
	pass, err := extractStr(resp, "turn_server", "credential")
	if err != nil {
		return nil, fmt.Errorf("step6 parse credential: %w", err)
	}

	turnServer, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("step6: turn_server not a map")
	}
	urls, ok := turnServer["urls"].([]interface{})
	if !ok || len(urls) == 0 {
		return nil, fmt.Errorf("step6: turn_server.urls empty")
	}
	turnURL, ok := urls[0].(string)
	if !ok {
		return nil, fmt.Errorf("step6: turn_server.urls[0] not string")
	}

	clean := strings.Split(turnURL, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return &TURNCreds{
		Username: user,
		Password: pass,
		Address:  address,
	}, nil
}
