package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)
import (
	"log"
)

type ApiResponse struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
}

type SessionInfo struct {
	Uid   string `json:"uid"`
	Token string `json:"tokenInfo"`
}

type ApiError struct {
	Message string `json:"message"`
}

const (
	SESSION_API_URL = "https://api.nodepay.org/api/auth/session"
	PING_API_URL    = "https://nw.nodepay.org/api/network/ping"
)

var tokenInfo string
var accountInfo *SessionInfo
var browserId string
var statusConnect int

const CONNECTION_CONNECTED = 1
const CONNECTION_DISCONNECTED = 2
const CONNECTION_NONE = 3

var retries int
var timeoutPing time.Duration = 55 * time.Minute
var pingTimeout *time.Timer

// Simulate local storage in memory
var localStorage = make(map[string]interface{})

// Call API and process the response
func callAPI(url string, data interface{}, token string) (*ApiResponse, error) {
	client := &http.Client{Transport: &http.Transport{
		//Proxy: http.ProxyURL(parse),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}}
	// Step 1: 发送预检 OPTIONS 请求
	optionsReq, err := http.NewRequest("OPTIONS", url, nil)
	if err != nil {
		fmt.Println("创建 OPTIONS 请求失败:", err)
		return nil, fmt.Errorf("error marshalling request data: %v", err)
	}
	// 设置必要的 CORS 头
	optionsReq.Header.Set("Accept", "*/*")
	optionsReq.Header.Set("Origin", "https://app.nodepay.ai")
	optionsReq.Header.Set("Referer", "https://app.nodepay.ai/")
	optionsReq.Header.Set("Access-Control-Request-Method", "POST")
	optionsReq.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	// 模拟 Chrome 的 User-Agent 头
	optionsReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	// 发送 OPTIONS 请求
	optionsResp, err := client.Do(optionsReq)
	if err != nil {
		fmt.Println("发送 OPTIONS 请求失败:", err)
		return nil, fmt.Errorf("error marshalling request data: %v", err)
	}
	defer optionsResp.Body.Close()

	// 检查 OPTIONS 请求是否成功
	if optionsResp.StatusCode != http.StatusOK {
		fmt.Println("OPTIONS 请求失败，状态码:", optionsResp.StatusCode)
		return nil, fmt.Errorf("error marshalling request data: %v", err)
	}
	fmt.Println("OPTIONS 请求成功")
	body, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshalling request data: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("accept", "*/*")
	req.Header.Set("user-agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-OK response: %d", resp.StatusCode)
	}

	// Read response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var apiResp ApiResponse
	err = json.Unmarshal(bodyBytes, &apiResp)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %v", err)
	}

	return &apiResp, nil
}

// Fetch session info and handle the response
func fetchSessionInfo() {
	resp, err := callAPI(SESSION_API_URL, nil, tokenInfo)
	if err != nil {
		log.Printf("Error fetching session info: %v", err)
		handleLogout()
		return
	}

	if resp.Code == 0 {
		sessionData := resp.Data.(map[string]interface{})
		if uid, ok := sessionData["uid"].(string); ok {
			accountInfo = &SessionInfo{
				Uid:   uid,
				Token: tokenInfo,
			}
			localStorage["np_session_info"] = accountInfo
			localStorage["np_session_expire_date"] = time.Now().Unix()
			statusConnect = CONNECTION_NONE
			connectSocket()
		}
	} else {
		log.Println("Session info not valid, logging out.")
		handleLogout()
	}
}

// Connect to socket (simulated in this case)
func connectSocket() {
	if browserId == "" {
		browserId = uuid.New().String()
		localStorage["browser_id"] = browserId
	}

	if statusConnect == CONNECTION_CONNECTED {
		log.Println("Already connected or in the process of connecting")
		return
	}

	// Start pinging
	ping()
}

// Ping API to keep connection alive
func ping() {
	// Clear previous timeout if any
	if pingTimeout != nil {
		pingTimeout.Stop()
	}

	// Data to be sent in the ping request
	data := map[string]interface{}{
		"id":         accountInfo.Uid,
		"browser_id": browserId,
		"timestamp":  time.Now().Unix(),
		"version":    "1.0.0", // Example version
	}

	_, err := callAPI(PING_API_URL, data, tokenInfo)
	if err != nil {
		retries++
		if retries < 6 {
			timeoutPing = 5 * time.Minute
		} else {
			timeoutPing = 55 * time.Minute
		}

		if retries < 2 {
			// Simulate setting IP score and status
			localStorage["ip_score_ws"] = rand.Intn(21) + 20
			localStorage["status_ws"] = CONNECTION_CONNECTED
		} else {
			statusConnect = CONNECTION_DISCONNECTED
			localStorage["ip_score_ws"] = 0
			localStorage["status_ws"] = CONNECTION_DISCONNECTED
		}
	} else {
		// Reset retries on successful ping
		retries = 0
		timeoutPing = 55 * time.Minute
		localStorage["ip_score_ws"] = rand.Intn(20) + 80
		localStorage["status_ws"] = CONNECTION_CONNECTED
		statusConnect = CONNECTION_CONNECTED
	}

	// Schedule next ping
	pingTimeout = time.AfterFunc(timeoutPing, ping)
}

// Handle logout and reset everything
func handleLogout() {
	statusConnect = CONNECTION_NONE
	tokenInfo = ""
	accountInfo = nil
	localStorage["np_session_info"] = nil
	localStorage["np_session_expire_date"] = nil
}

func main() {
	os.Setenv("http_proxy", "http://192.168.1.24:7897")
	os.Setenv("http_proxy", "http://192.168.1.24:7897")
	// Simulate token assignment (In real-world scenario, get it from external)
	tokenInfo = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMzAzODg3NzA1MTU4OTc1NDg4IiwiaWF0IjoxNzMxMTM5MTg2LCJleHAiOjE3MzIzNDg3ODZ9.aarOSpvn6bAqsk7eqMiYsxjHOKDvY2FgDDOHvxDcWIKxrEB4YtgvRjCDbwTRcAs9-fYQwBQw4w0_MjyvC2uFog"

	// Fetch session info to start the connection process
	fetchSessionInfo()

	// Block forever to keep the app running and periodically ping
	select {}
}
