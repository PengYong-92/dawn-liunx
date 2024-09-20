package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	api2captcha "github.com/2captcha/2captcha-go"
	"io"
	"log"
	"net/http"
	"net/url"
)

const (
	PROXY_URL = "http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_W5tYWcXDXD:S6DxmHXr@gate.nstproxy.io:24125"
)

func main() {
	//os.Setenv("http_proxy", "http://172.16.100.237:7899")
	//os.Setenv("https_proxy", "http://172.16.100.237:7899")
	code := hCaptcha()
	for {
		success := faucet("0x72d538CdC11Ef76A979be10D5533983b9734a383", code)
		if success {
			break
		}
	}

}

func hCaptcha() string {
	client := api2captcha.NewClient("4f491b55857cbe0a0f10a75c50524f65")
	captcha := api2captcha.HCaptcha{
		SiteKey: "06ee6b5b-ef03-4491-b8ea-01fb5a80256f",
		Url:     "https://faucet.0g.ai/",
	}
	code, s, err := client.Solve(captcha.ToRequest())
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("code：" + s)
	fmt.Println("code：" + code)
	return code
}

func faucet(address, code string) bool {
	proxyURL := flag.String("proxy", PROXY_URL, "代理 URL")
	proxy, err := url.Parse(*proxyURL)
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

	body := map[string]interface{}{
		"address":       address,
		"hcaptchaToken": code,
	}

	// 将body转换为JSON字符串
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		log.Fatalf("序列化JSON失败: %v", err)
	}

	// 发送POST请求
	baseRul := "https://faucet.0g.ai/api/faucet"
	req, err := http.NewRequest("POST", baseRul, bytes.NewBuffer(bodyJSON))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("content-type", "text/plain;charset=UTF-8")
	req.Header.Set("origin", "https://faucet.0g.ai")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("初始化失败：%s", baseRul)
		return false
	}
	defer resp.Body.Close()

	all, err := io.ReadAll(resp.Body)
	log.Println(string(all))
	if resp.StatusCode == http.StatusOK {
		s := toJSON(all)
		fmt.Println(s)
	}
	return false
}

func toJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
