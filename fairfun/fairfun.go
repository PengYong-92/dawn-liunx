package main

import (
	"blockmesh/utils"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	PROXY_URL    = "http://2892ED58F5DF1579-residential-country_US-r_0m-s_PDfBsmnJTM:Qbb645Mf@gw-us.nstproxy.com:24125"
	BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)

func main() {
	os.Setenv("HTTP_PROXY", "http://127.0.0.1:7897")
	os.Setenv("HTTPS_PROXY", "http://127.0.0.1:7897")
	//parse, _ := url.Parse(PROXY_URL)
	client := &http.Client{
		Transport: &http.Transport{
			//Proxy: http.ProxyURL(parse),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	login(client)
}

func login(client *http.Client) (string, []*http.Cookie) {
	baseUrl := "https://fairfun.meme/passport/auth/twitter"

	req, err := http.NewRequest("GET", baseUrl, nil)
	if err != nil {
		log.Printf("初始化失败：%s", baseUrl)
		return "", nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36")
	req.Header.Set("Referer", "https://fairfun.meme/airdrop")
	req.Header.Set("HOST", "fairfun.meme")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("accept-language", "zh-CN,zh;q=0.9")
	req.Header.Set("priority", "u=1, i")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "cross-site")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// 禁止自动重定向
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("初始化失败：%s", baseUrl)
		return "", nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	if err != nil {
		log.Printf("读取body失败: %v", err)
		return "", nil
	}
	if 302 == resp.StatusCode {
		location := resp.Header.Get("Location")
		log.Printf("获取Location：%s", location)
		if len(location) > 20 {
			client_id, _ := utils.GetParameterValue(location, "client_id")
			state, _ := utils.GetParameterValue(location, "state")
			code_challenge, _ := utils.GetParameterValue(location, "code_challenge")
			twitter(client_id, state, code_challenge, "", client, "1066f9ffe3940a234ca29d9a47ee1dc49eb038a2")
		}
	}
	return "", nil
}

func twitter(clientId, state, codeChallenge, cookie string, client *http.Client, tToken string) (string, error) {
	baseURL := "https://twitter.com/i/api/2/oauth2/authorize"

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientId)
	params.Set("redirect_uri", "https://fairfun.meme/passport/auth/twitter/callback")
	params.Set("scope", "tweet.read users.read offline.access")
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	_, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
	req.Header.Set("authority", "x.com")
	req.Header.Set("HOST", "x.com")
	req.Header.Set("x-twitter-active-user", "yes")
	req.Header.Set("x-twitter-client-language", "en")
	req.Header.Set("Origin", "https://x.com")
	req.Header.Set("Authorization", "Bearer "+BEARER_TOKEN)

	// Add cookies
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "ct0", Value: cookie})
		req.Header.Set("x-csrf-token", cookie)
	}
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: tToken})
	clients := &http.Client{}
	resp, err := clients.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	status := resp.StatusCode
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}

	ct0Cookie := ""
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "ct0" {
			ct0Cookie = cookie.Value
		}
	}

	fmt.Printf("%d : %s\n", status, ct0Cookie)
	if status == http.StatusOK {
		if authCode, ok := response["auth_code"].(string); ok {
			return authCode, nil
		}
	} else if code, ok := response["code"].(float64); ok && int(code) == 353 {
		fmt.Printf("%s\n", response["message"].(string))
		time.Sleep(1000)
		auth, err := twitter(clientId, state, codeChallenge, ct0Cookie, client, tToken)
		if err != nil {
			return "", err
		}
		fmt.Printf("auth: %s\n", auth)
		TwitterAuthorize(auth, baseURL, client, tToken, ct0Cookie)
		return auth, nil
	}

	return "", nil
}
func TwitterAuthorize(authCode string, baseURL string, client *http.Client, ttoken, ct0 string) (string, error, bool) {
	formData := "approval=true&code=" + authCode
	log.Println("TwitterAuthorize authCode: " + authCode)
	baseReq, err := http.NewRequest("POST", baseURL, strings.NewReader(formData))
	if err != nil {
		log.Printf("%s 推特授权异常：%v", authCode, err)
		return "", err, true
	}
	//baseReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
	baseReq.Header.Set("authority", "x.com")
	baseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	baseReq.Header.Set("HOST", "x.com")
	baseReq.Header.Set("x-twitter-active-user", "yes")
	baseReq.Header.Set("x-twitter-client-language", "en")
	baseReq.Header.Set("Origin", "https://x.com")
	baseReq.Header.Set("Authorization", "Bearer "+BEARER_TOKEN)
	baseReq.AddCookie(&http.Cookie{Name: "ct0", Value: ct0})
	baseReq.Header.Set("x-csrf-token", ct0)
	baseReq.AddCookie(&http.Cookie{Name: "auth_token", Value: ttoken})

	clients := &http.Client{}
	baseResp, err := clients.Do(baseReq)
	if err != nil {
		log.Printf("%s 推特授权异常：%v", authCode, err)
		return "", err, true
	}
	defer baseResp.Body.Close()
	body, err := io.ReadAll(baseResp.Body)
	if err != nil {
		log.Printf("%s 推特授权异常：%v", authCode, err)
		return "", err, false
	}
	fmt.Printf("TwitterAuthorize Status: %s\n", baseResp.Status)
	fmt.Printf("TwitterAuthorize body: %s\n", body)
	if baseResp.StatusCode == http.StatusTooManyRequests {
		log.Printf("%s 请求过多，等待5秒", authCode)
		time.Sleep(5 * time.Second)
		TwitterAuthorize(authCode, baseURL, client, ttoken, ct0)

	}
	if baseResp.StatusCode == http.StatusOK {
		// 检查响应体中是否包含redirect_uri
		redirectURI := extractRedirectURI(body)
		if redirectURI != "" {
			fmt.Printf("推特授权成功，redirect_uri: %s\n", redirectURI)
			return authCode, err, true
		}
	}
	return "", nil, false
}

func extractRedirectURI(body []byte) string {
	// 在这里解析响应体，提取出redirect_uri
	// 具体解析方法可能需要根据实际的响应结构进行调整
	// 假设返回的是JSON结构
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("解析响应体时出错: %v", err)
		return ""
	}

	if redirectURI, ok := result["redirect_uri"].(string); ok {
		return redirectURI
	}

	return ""
}
