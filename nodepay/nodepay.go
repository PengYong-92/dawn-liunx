package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/valyala/fasthttp"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func main() {
	os.Setenv("http_proxy", "http://192.168.1.24:7897")
	os.Setenv("http_proxy", "http://192.168.1.24:7897")
	//user := "pengy6130@gmail.com"
	//password := "Aa121254088."
	//apikey := "CAP-AD9D27597DA91DE289B7B63CFAE3CB4A"
	//ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
	//defer cancel()
	//
	//res, err := solver.Cloudflare(ctx, apikey, map[string]any{
	//	"type":       "AntiTurnstileTaskProxyLess",
	//	"websiteURL": "https://app.nodepay.ai/",
	//	"websiteKey": "0x4AAAAAAAx1CyDNL8zOEPe7",
	//})
	//if err == nil {
	//	captcha := res.Solution["token"].(string)
	//	fmt.Println(captcha)
	//	cookies, err := OptionsLogin()
	//	if err != nil {
	//		log.Fatalf("OptionsLogin failed: %v", err)
	//	}
	//
	//	for _, cookie := range cookies {
	//		fmt.Printf("Cookie Name: %s, Value: %s\n", cookie.Name, cookie.Value)
	//	}
	//	logins, err := Login(user, password, captcha, cookies)
	//	fmt.Printf(utils.ToJSON(logins))
	//} else {
	//	fmt.Println("Error:", err)
	//}

	//cookies, err := OptionsLogin()
	//if err != nil {
	//	log.Fatalf("OptionsLogin failed: %v", err)
	//}
	//for _, cookie := range cookies {
	//	fmt.Printf("Cookie Name: %s, Value: %s\n", cookie.Name, cookie.Value)
	//}

	client := &fasthttp.Client{}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// 设置请求方法和URL
	req.SetRequestURI("https://api.nodepay.org/api/auth/login")
	req.Header.SetMethod("OPTIONS")

	// 设置浏览器的User-Agent和其他标头
	// 模拟Chrome浏览器的完整Headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	req.Header.Set("Origin", "https://app.nodepay.ai") // 替换为实际来源
	req.Header.Set("Referer", "https://app.nodepay.ai/")
	// 发起请求
	err := client.Do(req, resp)
	if err != nil {
		fmt.Printf("请求失败: %s\n", err)
		return
	}

	// 检查状态码和响应内容
	fmt.Printf("状态码: %d\n", resp.StatusCode())
	fmt.Printf("响应内容: %s\n", resp.Body())

}

// LoginRequest 定义了请求体的结构
type LoginRequest struct {
	User           string `json:"user"`
	Password       string `json:"password"`
	RememberMe     bool   `json:"remember_me"`
	RecaptchaToken string `json:"recaptcha_token"`
}

// LoginResponse 定义了登录响应的结构
type LoginResponse struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Data    struct {
		Token     string `json:"token"`
		ExpiresIn string `json:"expires_in"`
		UserInfo  struct {
			UID                string      `json:"uid"`
			Name               string      `json:"name"`
			Email              string      `json:"email"`
			Avatar             string      `json:"avatar"`
			ReferralCode       string      `json:"referral_code"`
			State              string      `json:"state"`
			ReferralLink       string      `json:"referral_link"`
			Balance            interface{} `json:"balance"` // 这里是 null，使用 interface{}
			NetworkEarningRate float64     `json:"network_earning_rate"`
		} `json:"user_info"`
	} `json:"data"`
}

// Login 响应登录请求，返回响应体和错误
func Login(user, password, recaptchaToken string, cookies []*http.Cookie) (*LoginResponse, error) {
	// 创建请求体
	loginRequest := LoginRequest{
		User:           user,
		Password:       password,
		RememberMe:     true,
		RecaptchaToken: recaptchaToken,
	}

	// 将请求体编码为 JSON
	requestBody, err := json.Marshal(loginRequest)
	if err != nil {
		return nil, fmt.Errorf("JSON Marshal error: %v", err)
	}
	// 创建请求
	req, err := http.NewRequest("POST", "https://api.nodepay.org/api/auth/login?", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("NewRequest error: %v", err)
	}

	// 设置请求头
	req.Header.Set("Host", "api.nodepay.org")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://app.nodepay.ai")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36")
	req.Header.Set("Referer", "https://app.nodepay.ai/")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("priority", "u=1, i")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "cross-site")

	if cookies != nil {
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		req.AddCookie(&http.Cookie{Name: "", Value: ""})
	}
	// 发送请求
	client := &http.Client{
		Transport: &http.Transport{
			//Proxy: http.ProxyURL(parse),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// 禁止自动重定向
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	// 打印返回的状态码和 Content-Type
	fmt.Printf("Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Content-Type: %s\n", resp.Header.Get("Content-Type"))
	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	// 打印返回的 HTML 内容，查看是否为错误页面
	fmt.Println("Response Body (HTML):", string(body))
	// 如果状态码是 403，返回 cookies
	if resp.StatusCode == http.StatusOK {
		if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			// 解析 JSON 响应
			var loginResponse LoginResponse
			err := json.Unmarshal(body, &loginResponse)
			if err != nil {
				return nil, fmt.Errorf("failed to parse JSON response: %v", err)
			}
			return &loginResponse, nil
		}
	}
	return nil, nil
}

// OptionsLogin 发送一个 OPTIONS 请求，并根据返回的状态码判断是否返回 cookies
func OptionsLogin() ([]*http.Cookie, error) {
	// 创建 OPTIONS 请求
	req, err := http.NewRequest(http.MethodOptions, "https://api.nodepay.org/api/auth/login?", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OPTIONS request: %v", err)
	}

	// 设置请求头
	req.Header.Set("Accept", "*/*")
	//req.Header.Set("accept-encoding", "gzip, deflate, br, zstd")
	//req.Header.Set("accept-language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Origin", "https://app.nodepay.ai")
	req.Header.Set("Referer", "https://app.nodepay.ai/")
	//req.Header.Set("sec-fetch-dest", "empty")
	//req.Header.Set("sec-fetch-mode", "cors")
	//req.Header.Set("sec-fetch-site", "cross-site")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
	//req.Header.Set("Connection", "keep-alive")
	//req.Header.Set("Priority", "u=1, i")
	req.Header.Set("Sec-Ch-Ua", "\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\"")
	//req.Header.Set("sec-ch-ua-platform", "Windows")
	//req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Println(resp.StatusCode)
	fmt.Println(resp.Header.Get("content-security-policy"))
	// 如果状态码是 403，返回 cookies
	if resp.StatusCode == http.StatusForbidden {
		// 获取 cookies
		cookies := resp.Cookies()
		return cookies, nil
	}
	// 如果不是 403，返回空和状态码
	return nil, fmt.Errorf("Received unexpected status code: %d", resp.StatusCode)
}
