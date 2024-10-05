package main

import (
	"blockmesh/utils"
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	api2captcha "github.com/2captcha/2captcha-go"
	"github.com/go-resty/resty/v2"
	"github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"time"
)

var logger *zap.Logger

const (
	CAPT_KEY = "4f491b55857cbe0a0f10a75c50524f65"
)

func main() {
	_ = os.Setenv("http_proxy", "http://172.16.100.237:7899")
	_ = os.Setenv("https_proxy", "http://172.16.100.237:7899")
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

	var fileAddress string
	var cakey string

	flag.StringVar(&fileAddress, "address", "", "文件地址")
	flag.StringVar(&cakey, "cakey", "", "验证码KEY")
	flag.Parse()

	if fileAddress == "" {
		logger.Error("地址为空")
		return
	}
	if cakey == "" {

	}

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
			//ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
			//defer cancel()
			//taskData := map[string]any{
			//	"type":       "HCaptchaTaskProxyLess",
			//	"websiteURL": "https://faucet.vana.org/",
			//	"websiteKey": "b84448b5-ba29-4e90-9451-971f40fb6861",
			//}
			captcha := hCaptcha()
			//captcha, err := solver.HCaptcha(ctx, cakey, taskData) // 获取 hCaptcha 验证码
			//if err != nil {
			//	logger.Error("验证码错误：", zap.Error(err))
			//}
			if captcha != "" {
				code = captcha
				break
			}

		}

		success := false
		for i := 0; i < 10; i++ {
			// 解析代理 URL
			//eee, err := url.Parse(proxyUrls[i])
			//if err != nil {
			//	logger.Error("解析代理 URL 失败: ", zap.String("proxyUrl", proxyUrls[i]))
			//	continue
			//}
			client := resty.New().
				SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
				SetHeader("content-type", "text/plain;charset=UTF-8").
				SetHeader("origin", "https://faucet.vana.org").
				SetHeader("accept", "*/*").
				SetHeader("accept-language", "en-US,en;q=0.9").
				SetHeader("priority", "u=1, i").
				SetHeader("sec-fetch-dest", "empty").
				SetHeader("sec-fetch-mode", "cors").
				SetHeader("sec-fetch-site", "cross-site").
				SetHeader("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36").
				SetHeader("referer", "https://faucet.vana.org/moksha")
			success = sendPost(client, code, address, proxyUrls[i])
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
	err = utils.WriteAddressesToFile(fileAddress, remainingAddresses)
	if err != nil {
		logger.Error("写入文件错误：", zap.String("file", fileAddress), zap.Error(err))
		return
	}

	logger.Info("处理完毕，文件已更新", zap.String("file", fileAddress))
}

func sendPost(client *resty.Client, captcha, address, proxyUrl string) bool {
	reqBody := map[string]interface{}{
		"address": address,
		"captcha": captcha,
		"network": "moksha",
	}

	post, err := client.SetProxy(proxyUrl).R().
		SetBody(utils.ToJSON(reqBody)).
		Post("https://faucet.vana.org/api/transactions")
	if err != nil {
		logger.Error("请求错误：", zap.Error(err))
		return false
	}

	logger.Info("返回数据：" + string(post.Body()))
	var responseResult map[string]interface{}
	err = json.Unmarshal(post.Body(), &responseResult)
	if err != nil {
		logger.Error("解析错误：", zap.Error(err))
		time.Sleep(3 * time.Minute)
		return false
	}

	if responseResult["message"] != nil && responseResult["message"].(string) == "Transaction successful!" {
		return true
	}

	return false
}
func hCaptcha() string {
	client := api2captcha.NewClient(CAPT_KEY)
	captcha := api2captcha.HCaptcha{
		SiteKey: "b84448b5-ba29-4e90-9451-971f40fb6861",
		Url:     "https://faucet.vana.org/",
	}
	code, _, err := client.Solve(captcha.ToRequest())
	if err != nil {
		logger.Error("验证码错误：", zap.Error(err))
		return ""
	}
	//logger.Info("验证码：", zap.String("code：", code))
	return code
}
