package main

import (
	"blockmesh/solver"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/playwright-community/playwright-go"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	proxyUrl = "http://2892ED58F5DF1579-residential-country_US-r_0m-s_PDfBsmnJTM:Qbb645Mf@gw-us.nstproxy.com:24125"
)

func main() {
	// 启动 Playwright
	pw, err := playwright.Run()
	if err != nil {
		log.Fatalf("could not start Playwright: %v", err)
	}
	defer pw.Stop()

	// 启动 Chromium 浏览器
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true), // 使用无头模式
	})
	if err != nil {
		log.Fatalf("could not launch browser: %v", err)
	}
	defer browser.Close()

	// 创建新的浏览器上下文
	context, err := browser.NewContext()
	if err != nil {
		log.Fatalf("could not create browser context: %v", err)
	}

	// 创建新的页面
	page, err := context.NewPage()
	if err != nil {
		log.Fatalf("could not create page: %v", err)
	}

	// 下载 JavaScript 文件内容
	jsURL := "https://faucet.story.foundation/.well-known/vercel/security/static/challenge.v2.min.js"
	jsCode, err := downloadJavaScript(jsURL)
	if err != nil {
		log.Fatalf("could not download JavaScript file: %v", err)
	}

	// 在页面中执行 JavaScript
	result, err := page.Evaluate(fmt.Sprintf(`
        (() => {
            %s
            // Return something if needed
            return 'JavaScript executed';
        })()
    `, jsCode))
	if err != nil {
		log.Fatalf("could not evaluate JavaScript: %v", err)
	}

	// 打印结果
	fmt.Println("Execution result:", result)
}

// downloadJavaScript 从指定的 URL 下载 JavaScript 文件内容
func downloadJavaScript(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	jsCode, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(jsCode), nil
}

func requestChallenge(client *http.Client) {
	url := "https://faucet.story.foundation/.well-known/vercel/security/request-challenge"
	method := "GET"

	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Origin", "https://faucet.story.foundation")
	req.Header.Add("Referer", "https://faucet.story.foundation/.well-known/vercel/security/static/challenge.v2.min.js")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36")
	req.Header.Add("Accept", "*/*")
	req.Header.Add("Host", "faucet.story.foundation")
	req.Header.Add("Connection", "keep-alive")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(body))

}

func toJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func login(client *http.Client) {
	providersUrl := "https://faucet.story.foundation/api/auth/providers"
	req, err := http.NewRequest("GET", providersUrl, nil)
	if err != nil {
		log.Printf("初始化失败：%s", providersUrl)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("初始化失败：%s", providersUrl)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取body失败: %v", err)
		return
	}
	bodyJson := toJSON(body)
	log.Printf("providers返回：%s", bodyJson)
}

func waters() {
	captcha := getCaptcha()

	proxy, err := url.Parse(proxyUrl)
	if err != nil {
		log.Fatalf("解析代理 URL 失败: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// 要发送的请求数据（JSON 格式）
	requestData := []map[string]string{
		{
			//"address":  "0x2693034bA44E825d5509551f6c24bEc04c28b907",
			"address":  "0x43b38Ebc793EC29Ab681D82d66d47C7750e62a2e",
			"token":    captcha,
			"id":       uuid.New().String(),
			"provider": "X",
		},
	}

	// 将请求数据编码为 JSON
	jsonData, err := json.Marshal(requestData)

	if err != nil {
		fmt.Println("JSON 编码失败:", err)
		return
	}
	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", "https://faucet.story.foundation", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}
	// 设置请求头

	req.Header.Set("Host", "faucet.story.foundation")
	req.Header.Set("Accept-Language", "zh-CN")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36")
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Accept", "text/x-component")
	req.Header.Set("Origin", "https://faucet.story.foundation")
	req.Header.Set("Referer", "https://faucet.story.foundation/")
	req.Header.Set("Next-Action", "27a9a1a8a0473e1b57bad88838fdb5b8e6fe884b")
	req.Header.Set("Baggage", "sentry-environment=production,sentry-release=decf9258eafd26859503c89ac1d1d14046d2b1ea,sentry-public_key=5e6110065ec53581495808b74e151292,sentry-trace_id=47fd2b30582d46a48b19e115ed3ac9c5,sentry-sample_rate=1,sentry-sampled=true")
	req.Header.Set("Sentry-Trace", "47fd2b30582d46a48b19e115ed3ac9c5-93753971402c732a-1")

	req.AddCookie(&http.Cookie{Name: "_vcrcs", Value: "1.1725530036.3600.OTRkNDU2MzJlNzkyMGI4MjA0YTkyM2RlMDg5MTZkM2Y=.7a466d1b67eacac9b68a218ef9bef8de"})
	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 输出响应
	fmt.Println("响应状态码:", resp.StatusCode)
	fmt.Println("响应体:", string(body))
}

func getCaptcha() string {
	var captcha string
	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {

		apikey := "CAP-C7314376D9418C07CF7CB36FEBF1C62B"
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
		defer cancel()

		res, err := solver.Cloudflare(ctx, apikey, map[string]any{
			"type":       "AntiTurnstileTaskProxyLess",
			"websiteURL": "https://faucet.story.foundation/",
			"websiteKey": "0x4AAAAAAAgnLZFPXbTlsiiE",
		})
		if err == nil {
			captcha = res.Solution["token"].(string)
			fmt.Println("SUCCESS captcha")
			break
		}
		log.Printf("solver.CapSolver 调用失败: %v", err)
		if i < maxRetries-1 {
			log.Printf("重试 %d/%d", i+1, maxRetries)
			time.Sleep(time.Second * 2) // 等待一段时间再重试
		} else {
			log.Printf("重试次数已用尽")
			return ""
		}
	}
	return captcha
}
