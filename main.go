package main

import (
	"blockmesh/constant"
	"blockmesh/request"
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	api2captcha "github.com/2captcha/2captcha-go"
	"github.com/go-resty/resty/v2"
	"github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"image"
	"image/color"
	_ "image/gif"
	"image/jpeg"
	_ "image/jpeg"
	_ "image/png"
	"io/ioutil"
	"log"
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

const (
	//PROXY__URL = "http://2892ED58F5DF1579-residential-country_US-r_0m-s_PDfBsmnJTM:Qbb645Mf@gw-us.nstproxy.com:24125"
	PROXY__URL = "http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_zGLKzDNgUV:S6DxmHXr@gate.nstproxy.io:24125"
)

func main() {
	// 设置代理
	//_ = os.Setenv("https_proxy", "http://172.16.100.237:7899")
	//_ = os.Setenv("http_proxy", "http://172.16.100.237:7899")
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
		time.Sleep(2 * time.Minute)
	}

	select {}

	//saveBase64ToFile(grayscale, "output.png")

}

/*
	func saveBase64ToFile(imgBase64, fileName string) error {
		imgBase64 = strings.Split(imgBase64, ",")[1]
		imgData, err := base64.StdEncoding.DecodeString(imgBase64)
		if err != nil {
			return err
		}
		return os.WriteFile(fileName, imgData, 0644)
	}
*/
func convertToGrayScale(imgBase64 string) string {
	// 解码 Base64
	imgData, err := base64.StdEncoding.DecodeString(imgBase64)
	if err != nil {
		log.Fatalf("解码 Base64 失败: %v", err)
	}

	// 解码图像（支持自动检测格式）
	img, _, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		log.Fatalf("解码图像失败: %v", err)
	}

	// 创建一个新的灰度图像
	bounds := img.Bounds()
	grayImg := image.NewGray(bounds)
	// 调整灰度值的因子
	darkenFactor := 0.2 // 取值范围 0-1，0 表示完全黑色，1 表示原始灰度

	// 遍历原图像的每个像素，并将其转换为加深的灰度
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			originalColor := img.At(x, y)
			grayColor := color.GrayModel.Convert(originalColor).(color.Gray)
			// 调整灰度值
			newGrayValue := uint8(float64(grayColor.Y) * darkenFactor)
			grayImg.Set(x, y, color.Gray{Y: newGrayValue})
		}
	}

	// 将加深的灰度图像编码为 JPEG 格式
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, grayImg, nil); err != nil {
		log.Fatalf("编码灰度图像失败: %v", err)
	}

	// 将 JPEG 编码的数据转换为 Base64
	grayBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	// 返回新的 Base64 编码字符串，带上前缀 "data:image/jpeg;base64,"
	return grayBase64
}

func ping(email string) {
	rand.Seed(time.Now().UnixNano())
	//client := resty.New().SetProxy("http://2892ED58F5DF1579-residential-country_US-r_0m-s_PDfBsmnJTM:Qbb645Mf@gw-us.nstproxy.com:24125").
	client := resty.New().SetProxy(PROXY__URL).
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

	da, pizzId := captcha(client)
	if len(da) < 5 {
		logger.Info("识别错误：" + da)
		time.Sleep(2 * time.Second)
		go ping(email)
		return
	}
	// 判断 trim 是否包含换行符或空格
	if strings.Contains(da, "\n") || strings.Contains(da, "\r\n") {
		logger.Info("识别结果包含换行符")
		time.Sleep(2 * time.Second)
		go ping(email)
		return
	}

	if strings.Contains(da, " ") {
		logger.Info("识别结果包含空格")
		time.Sleep(2 * time.Second)
		go ping(email)
		return
	}

	loginRequest := request.LoginRequest{
		Username: email,
		Password: "1qazXSW@dwan",
		PuzzleId: pizzId,
		Ans:      da,
		Logindata: struct {
			V        string `json:"_v"`
			Datetime string `json:"datetime"`
		}(struct {
			V        string
			Datetime string
		}{V: "1.0.8", Datetime: time.Now().Format("2006-01-02 15:04:05")}),
	}
	var loginResponse request.LoginResponse
	res, err := client.R().
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

	// 解析 JSON 响应
	//var result map[string]interface{}
	//err = json.Unmarshal(res.Body(), &result)
	log.Printf(res.String())

	//登录失败重试
	var result map[string]interface{}
	err = json.Unmarshal(res.Body(), &result)
	if nil == result["data"] {
		time.Sleep(2 * time.Second)
		go ping(email)
		return
	}

	keepAliveRequest := map[string]interface{}{
		"username":     email,
		"extensionid":  "fpdkjdnhkakefebpekbdhillbhonfjjp",
		"numberoftabs": 0,
		"_v":           "1.0.8",
	}
	// 定义一个用于解析的结构体
	/*	type Response struct {
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
	}*/

	go updateProfile(loginResponse.Data.Token, client)

	for {
		if time.Now().Sub(lastLogin) > 2*time.Hour {
			loginRequest.Logindata.Datetime = time.Now().Format("2006-01-02 15:04:05")
			_, err := client.SetProxy(PROXY__URL).R().
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
		res, err := client.SetProxy(PROXY__URL).R().
			SetHeader("authorization", fmt.Sprintf("Bearer %v", loginResponse.Data.Token)).
			SetBody(keepAliveRequest).
			Post(constant.KeepAliveURL)
		if err != nil {
			logger.Error("Keep alive error", zap.String("acc", email), zap.Error(err))
			time.Sleep(3 * time.Minute)
			continue
		}
		logger.Info("Keep alive success", zap.String("acc", email), zap.String("res", res.String()))

		res, err = client.SetProxy(PROXY__URL).R().
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
		twitterXIdPoints, ok := rewardPoint["twitter_x_id_points"].(float64)
		discordidPoints, ok := rewardPoint["discordid_points"].(float64)
		telegramidPoints, ok := rewardPoint["telegramid_points"].(float64)

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
			Points:    points + twitterXIdPoints + discordidPoints + telegramidPoints,
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
		logger.Info("上传信息返回：" + toJSON(response))
		time.Sleep(3 * time.Minute)
	}
}
func toJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
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
func captcha(client *resty.Client) (string, string) {
	get, err := client.SetProxy(PROXY__URL).R().Get("https://www.aeropres.in/chromeapi/dawn/v1/puzzle/get-puzzle")
	if err != nil {
		log.Printf("Failed to get JISUAN puzzle: %v", err)
		return "", ""
	}
	// 解析 JSON 响应
	var result map[string]interface{}
	err = json.Unmarshal(get.Body(), &result)
	if err != nil {
		logger.Error("请求错误，暂停5分钟", zap.Error(err))
		time.Sleep(5 * time.Minute)
		return "", ""
	}
	puzzleId := result["puzzle_id"].(string)
	response, err := client.SetProxy(PROXY__URL).R().Get("https://www.aeropres.in/chromeapi/dawn/v1/puzzle/get-puzzle-image?puzzle_id=" + puzzleId)
	if err != nil {
		logger.Error("请求错误，暂停5分钟", zap.Error(err))
		time.Sleep(5 * time.Minute)
		return "", ""
	}
	var responseResult map[string]interface{}
	err = json.Unmarshal(response.Body(), &responseResult)
	if err != nil {
		logger.Error("Failed to parse JSON", zap.Error(err))
		time.Sleep(3 * time.Minute)
		return "", ""
	}
	if responseResult["success"].(bool) == true {
		imgBase64 := responseResult["imgBase64"].(string)
		grayscale := convertToGrayScale(imgBase64)
		s := jisuan(grayscale)
		return s, puzzleId
	}
	return "", ""
}

// jisuan 发送OCR请求并计算表达式结果
func jisuan(imgBase64 string) string {
	body := map[string]interface{}{
		"base64": imgBase64,
		"options": map[string]string{
			"data.format": "text",
		},
	}

	// 将body转换为JSON字符串
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		log.Fatalf("序列化JSON失败: %v", err)
	}

	// 发送POST请求
	//resp, err := http.Post("http://127.0.0.1:1224/api/ocr", "application/json", bytes.NewBuffer(bodyJSON))
	resp, err := http.Post("http://107.148.176.146:1224/api/ocr", "application/json", bytes.NewBuffer(bodyJSON))
	if err != nil {
		log.Fatalf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 解析响应
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("解析响应失败: %v", err)
		return ""
	}

	// 格式化表达式，确保运算符前后有空格
	//re := regexp.MustCompile(`([+\-*/])`)
	//trim = re.ReplaceAllString(trim, " $1 ")

	// 计算表达式结果
	//v := evaluateExpression(trim)

	data := result["data"].(string)
	trim := strings.TrimSpace(data)
	logger.Info("识别结果: " + trim)
	return trim
}

func updateProfile(token string, client *resty.Client) {
	twitterRequest := map[string]interface{}{
		"twitter_x_id": "twitter_x_id",
	}
	twitter, err := client.SetProxy(PROXY__URL).R().
		SetHeader("authorization", fmt.Sprintf("Bearer %v", token)).
		SetHeader("content-type", "application/json").
		SetBody(twitterRequest).
		Post("https://www.aeropres.in/chromeapi/dawn/v1/profile/update")
	if err != nil {
		logger.Error("请求twitter异常", zap.Error(err))
		return
	}
	logger.Info("请求twitter：" + twitter.String())

	time.Sleep(3 * time.Second)

	discordidRequest := map[string]interface{}{
		"discordid": "discordid",
	}
	discordid, err := client.SetProxy(PROXY__URL).R().
		SetHeader("authorization", fmt.Sprintf("Bearer %v", token)).
		SetHeader("content-type", "application/json").
		SetBody(discordidRequest).
		Post("https://www.aeropres.in/chromeapi/dawn/v1/profile/update")
	if err != nil {
		logger.Error("请求discord异常", zap.Error(err))
		return
	}
	logger.Info("请求discord：" + discordid.String())

	time.Sleep(3 * time.Second)

	telegramidRequest := map[string]interface{}{
		"telegramid": "telegramid",
	}

	telegramid, err := client.SetProxy(PROXY__URL).R().
		SetHeader("authorization", fmt.Sprintf("Bearer %v", token)).
		SetHeader("content-type", "application/json").
		SetBody(telegramidRequest).
		Post("https://www.aeropres.in/chromeapi/dawn/v1/profile/update")
	if err != nil {
		logger.Error("请求telegra异常", zap.Error(err))
		return
	}
	logger.Info("请求telegra：" + telegramid.String())
}

/**在线识别验证码*/
func getLoginCode(base64 string) string {
	client := api2captcha.NewClient("4f491b55857cbe0a0f10a75c50524f65")
	captcha := api2captcha.Normal{
		Base64: base64,
	}
	code, _, err := client.Solve(captcha.ToRequest())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("识别结果：" + code)
	return code
}
