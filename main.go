package main

import (
	"blockmesh/constant"
	"blockmesh/request"
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var lock struct {
	sync.Mutex // <-- this mutex protects
}

var logger *zap.Logger

func main() {
	// 设置代理
	_ = os.Setenv("https_proxy", "http://172.16.100.237:7899")
	_ = os.Setenv("http_proxy", "http://172.16.100.237:7899")
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger = zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(config),
		zapcore.AddSync(colorable.NewColorableStdout()),
		zapcore.DebugLevel,
	))
	file, err := os.Open("./email.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		go ping(scanner.Text())
		time.Sleep(3 * time.Second)
	}

	select {}

}

func ping(email string) {
	rand.Seed(time.Now().UnixNano())
	//client := resty.New().SetProxy(proxyURL).
	client := resty.New().
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetHeader("content-type", "application/json").
		SetHeader("origin", "chrome-extension://fpdkjdnhkakefebpekbdhillbhonfjjp").
		SetHeader("accept", "*/*").
		SetHeader("accept-language", "en-US,en;q=0.9").
		SetHeader("priority", "u=1, i").
		SetHeader("sec-fetch-dest", "empty").
		SetHeader("sec-fetch-mode", "cors").
		SetHeader("sec-fetch-site", "cross-site").
		SetHeader("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")

	loginRequest := request.LoginRequest{
		Username: email,
		Password: "1qazXSW@dwan",
		Logindata: struct {
			V        string `json:"_v"`
			Datetime string `json:"datetime"`
		}(struct {
			V        string
			Datetime string
		}{V: "1.0.6", Datetime: time.Now().Format("2006-01-02 15:04:05")}),
	}
	var loginResponse request.LoginResponse
	_, err := client.R().
		SetBody(loginRequest).
		SetResult(&loginResponse).
		Post(constant.LoginURL)
	if err != nil {
		logger.Error("Login error", zap.String("acc", email), zap.Error(err))
		time.Sleep(2 * time.Minute)
		go ping(email)
		return
	}
	lastLogin := time.Now()

	keepAliveRequest := map[string]interface{}{
		"username":     email,
		"extensionid":  "fpdkjdnhkakefebpekbdhillbhonfjjp",
		"numberoftabs": 0,
		"_v":           "1.0.6",
	}
	// 定义一个用于解析的结构体
	type Response struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
		Data    struct {
			ReferralPoint struct {
				Email string `json:"email"`
			} `json:"referralPoint"`
			RewardPoint struct {
				Points float64 `json:"points"`
			} `json:"rewardPoint"`
		} `json:"data"`
	}
	for {
		if time.Now().Sub(lastLogin) > 2*time.Hour {
			loginRequest.Logindata.Datetime = time.Now().Format("2006-01-02 15:04:05")
			_, err := client.R().
				SetBody(loginRequest).
				SetResult(&loginResponse).
				Post(constant.LoginURL)
			if err != nil {
				logger.Error("Login error", zap.String("acc", email), zap.Error(err))
				time.Sleep(1 * time.Minute)
				go ping(email)
				return
			}
		}

		res, err := client.R().
			SetHeader("authorization", fmt.Sprintf("Bearer %v", loginResponse.Data.Token)).
			SetBody(keepAliveRequest).
			Post(constant.KeepAliveURL)
		if err != nil {
			logger.Error("Keep alive error", zap.String("acc", email), zap.Error(err))
		}
		logger.Info("Keep alive success", zap.String("acc", email), zap.String("res", res.String()))

		res, err = client.R().
			SetHeader("authorization", fmt.Sprintf("Bearer %v", loginResponse.Data.Token)).
			Get(constant.GetPointURL)
		if err != nil {
			logger.Error("Get point error", zap.String("acc", email), zap.Error(err))
			time.Sleep(3 * time.Minute)
			continue
		}
		logger.Info("Get point success", zap.String("acc", email), zap.String("res", res.String()))
		// 解析 JSON 响应
		var result map[string]interface{}
		err = json.Unmarshal(res.Body(), &result)
		if err != nil {
			logger.Error("Failed to parse JSON", zap.Error(err))
			time.Sleep(3 * time.Minute)
			continue
		}

		// 提取 acc 和 points
		acc := email // 已知的 acc
		resData, ok := result["data"].(map[string]interface{})
		if !ok {
			logger.Error("Failed to get data from response")
			time.Sleep(3 * time.Minute)
			continue
		}

		rewardPoint, ok := resData["rewardPoint"].(map[string]interface{})
		if !ok {
			logger.Error("Failed to get rewardPoint from data")
			time.Sleep(3 * time.Minute)
			continue
		}

		points, ok := rewardPoint["points"].(float64)
		if !ok {
			logger.Error("Failed to get points from rewardPoint")
			time.Sleep(3 * time.Minute)
			continue
		}

		// 输出结果
		//fmt.Printf("acc: %s\n", acc)
		//fmt.Printf("points: %.2f\n", points)

		// 获取外网 IP 地址
		externalIP, err := GetExternalIP()
		if err != nil {
			fmt.Printf("Failed to get external IP: %v\n", err)
			time.Sleep(3 * time.Minute)
			continue
		}
		// 创建请求数据
		data := RequestData{
			Acc:       acc,
			Points:    points,
			IPAddress: externalIP,
		}

		// 发送请求并获取响应
		response, err := SendPostRequest("http://107.148.176.146:19900/points", data)
		if err != nil {
			fmt.Printf("Request failed: %v\n", err)
			time.Sleep(3 * time.Minute)
			continue
		}
		// 输出响应结果
		fmt.Printf("Response: %+v\n", response)

		time.Sleep(3 * time.Minute)
	}
}

type RequestData struct {
	Acc       string  `json:"acc"`
	Points    float64 `json:"points"`
	IPAddress string  `json:"ipAddress"`
}

// SendPostRequest 发送 POST 请求到指定 URL，携带 JSON 格式的请求数据
func SendPostRequest(url string, data RequestData) (map[string]interface{}, error) {
	// 将请求数据编码为 JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %v", err)
	}

	// 发送 POST 请求
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("error sending POST request: %v", err)
	}
	defer resp.Body.Close()

	// 解析响应
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	return result, nil
}

// GetExternalIP 获取当前服务器的外网 IP 地址
func GetExternalIP() (string, error) {
	resp, err := http.Get("http://ifconfig.me")
	if err != nil {
		return "", fmt.Errorf("failed to get external IP: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// 返回去除换行符的 IP 地址
	return strings.TrimSpace(string(body)), nil
}
