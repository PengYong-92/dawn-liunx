package main

import (
	"blockmesh/utils"
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	api2captcha "github.com/2captcha/2captcha-go"
	"github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var logger *zap.Logger

const (
	PROXY_URL   = "http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_W5tYWcXDXD:S6DxmHXr@gate.nstproxy.io:24125"
	CAPT_KEY    = "4f491b55857cbe0a0f10a75c50524f65"
	DEF_ADDRESS = "addresses.txt"
)

func main() {
	os.Setenv("http_proxy", "http://172.16.100.237:7899")
	os.Setenv("https_proxy", "http://172.16.100.237:7899")
	// 定义代理 URL 数组
	proxyUrls := []string{
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_vWtnUAbEEN:S6DxmHXr@gate.nstproxy.io:24125",
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_VqosVByQFz:S6DxmHXr@gate.nstproxy.io:24125",
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_9hfz1iZNwE:S6DxmHXr@gate.nstproxy.io:24125",
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_itlFUQKSMA:S6DxmHXr@gate.nstproxy.io:24125",
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_to6Enb9qOl:S6DxmHXr@gate.nstproxy.io:24125",
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_PTRlF2XOKI:S6DxmHXr@gate.nstproxy.io:24125",
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_sHdcu4DSX7:S6DxmHXr@gate.nstproxy.io:24125",
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_lqwxXKI9xw:S6DxmHXr@gate.nstproxy.io:24125",
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_W5tYWcXDXD:S6DxmHXr@gate.nstproxy.io:24125",
		"http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_zGLKzDNgUV:S6DxmHXr@gate.nstproxy.io:24125",
	}
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger = zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(config),
		zapcore.AddSync(colorable.NewColorableStdout()),
		zapcore.DebugLevel,
	))

	var proxyUrl string
	var fileAddress string

	flag.StringVar(&proxyUrl, "proxy", PROXY_URL, "代理 URL")
	flag.StringVar(&fileAddress, "address", DEF_ADDRESS, "文件地址")
	flag.Parse()

	// 解析代理 URL
	//proxy, err := url.Parse(proxyUrl)
	//if err != nil {
	//	logger.Error("解析代理 URL 失败: ", zap.String("proxyUrl", proxyUrl))
	//	return
	//}

	// 打开地址文件
	file, err := os.Open(fileAddress)
	if err != nil {
		logger.Error("读取文件错误：", zap.String("file", fileAddress))
		return
	}
	defer file.Close()

	// 读取文件内容到内存中
	var addresses []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		addresses = append(addresses, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		logger.Error("文件读取过程中发生错误", zap.String("file", fileAddress), zap.Error(err))
		return
	}

	// 创建一个空数组存储未成功的地址
	var remainingAddresses []string

	// 处理每个地址
	for _, address := range addresses {
		logger.Info("处理地址：", zap.String("ethAddress", address))
		var code string
		for i := 0; i < 3; i++ {
			code = hCaptcha() // 获取 hCaptcha 验证码
			if code != "" {
				break
			}
		}

		success := false
		for i := 0; i < 10; i++ {
			// 解析代理 URL
			eee, err := url.Parse(proxyUrls[i])
			if err != nil {
				logger.Error("解析代理 URL 失败: ", zap.String("proxyUrl", proxyUrls[i]))
				continue
			}
			success = faucet(address, code, eee) // faucet 函数处理
			if success {
				utils.SaveFailed(address, "success_address.txt") // 成功处理，保存到 success_address.txt
				break
			}
			time.Sleep(1 * time.Second)
		}

		// 如果成功，跳过此地址，否则保留地址以重新写回文件
		if !success {
			remainingAddresses = append(remainingAddresses, address)
		}
	}

	// 处理完毕，重新写入文件剩余地址
	err = writeAddressesToFile(fileAddress, remainingAddresses)
	if err != nil {
		logger.Error("写入文件错误：", zap.String("file", fileAddress), zap.Error(err))
		return
	}

	logger.Info("处理完毕，文件已更新", zap.String("file", fileAddress))
}

// 将剩余的地址重新写回文件
func writeAddressesToFile(fileAddress string, addresses []string) error {
	file, err := os.OpenFile(fileAddress, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, address := range addresses {
		_, err := writer.WriteString(address + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

func hCaptcha() string {
	client := api2captcha.NewClient(CAPT_KEY)
	captcha := api2captcha.HCaptcha{
		SiteKey: "06ee6b5b-ef03-4491-b8ea-01fb5a80256f",
		Url:     "https://faucet.0g.ai/",
	}
	code, _, err := client.Solve(captcha.ToRequest())
	if err != nil {
		fmt.Println(err)
		return ""
	}
	logger.Info("验证码：", zap.String("code：", code))
	return code
}

func faucet(address, code string, proxyURL *url.URL) bool {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
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
		logger.Error("序列化JSON失败：", zap.String("address：", address))
	}

	// 发送POST请求
	baseRul := "https://faucet.0g.ai/api/faucet"
	req, err := http.NewRequest("POST", baseRul, bytes.NewBuffer(bodyJSON))
	if err != nil {
		log.Print(err)
	}
	req.Header.Set("content-type", "text/plain;charset=UTF-8")
	req.Header.Set("origin", "https://faucet.0g.ai")
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("初始化失败：", zap.String("baseRul：", baseRul))
		return false
	}
	defer resp.Body.Close()

	all, err := io.ReadAll(resp.Body)
	logger.Info("请求返回：", zap.String("resp", string(all)))
	if resp.StatusCode == http.StatusOK {
		// 检查 message 是否以 "0x" 开头
		return isHexMessage(string(all))
	}
	return false
}

type Response struct {
	Message string `json:"message"`
}

func isHexMessage(jsonData string) bool {
	var res Response
	err := json.Unmarshal([]byte(jsonData), &res)
	if err != nil {
		logger.Error("Json转换失败：", zap.String("resp：", jsonData))
		return false
	}
	// 检查 message 是否以 "0x" 开头
	return strings.HasPrefix(res.Message, "0x")
}
