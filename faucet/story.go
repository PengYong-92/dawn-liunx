package main

import (
	"blockmesh/solver"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
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
