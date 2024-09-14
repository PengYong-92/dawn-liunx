package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"image"
	"image/color"
	_ "image/gif"
	"image/jpeg"
	_ "image/jpeg"
	_ "image/png"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

const (
	//proxyUrl = "http://2892ED58F5DF1579-residential-country_US-r_0m-s_PDfBsmnJTM:Qbb645Mf@gw-us.nstproxy.com:24125"
	proxyUrl = "http://EBF526E0437F7BF0-residential-country_DE-r_1m-s_zGLKzDNgUV:S6DxmHXr@gate.nstproxy.io:24125"
)

func main() {

	r := gin.Default()

	r.GET("/getCaptcha", captcha)
	r.POST("/submit", func(c *gin.Context) {
		// 读取请求体
		bodyBytes, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read body", "data": gin.H{"success": false, "message": "Incorrect answer. Try again!"}})
			return
		}

		// 恢复请求体，以便其他处理可以继续读取
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		// 将读取的 JSON 数据转换为字符串
		bodyString := string(bodyBytes)
		log.Println(bodyString)
		client := resty.New().SetProxy(proxyUrl).
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

		post, err := client.R().SetBody(bodyString).Post("https://www.aeropres.in/chromeapi/dawn/v1/puzzle/validate-register")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "data": gin.H{"success": false, "message": "Incorrect answer. Try again!"}})
			return
		}
		// 解析 JSON 响应
		var result map[string]interface{}
		err = json.Unmarshal(post.Body(), &result)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"message": err,
				"code":    2,
				"data":    gin.H{"success": false, "message": "Incorrect answer. Try again!"},
			})
			return
		}
		// 返回接收到的数据
		c.JSON(http.StatusOK, gin.H{
			"message": "Data received",
			"data":    result,
		})
	})
	_ = r.Run(":9090")
}

func captcha(c *gin.Context) {
	client := resty.New().SetProxy(proxyUrl).
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

	get, err := client.R().Get("https://www.aeropres.in/chromeapi/dawn/v1/puzzle/get-puzzle")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": err,
			"code":    1,
		})
		return
	}
	// 解析 JSON 响应
	var result map[string]interface{}
	err = json.Unmarshal(get.Body(), &result)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": err,
			"code":    2,
		})
		return
	}
	puzzleId := result["puzzle_id"].(string)
	response, err := client.R().Get("https://www.aeropres.in/chromeapi/dawn/v1/puzzle/get-puzzle-image?puzzle_id=" + puzzleId)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message":  err,
			"puzzleId": puzzleId,
			"code":     3,
		})
		return
	}
	var responseResult map[string]interface{}
	err = json.Unmarshal(response.Body(), &responseResult)
	if err != nil {
		log.Printf("Failed to parse JSON")
		c.JSON(http.StatusOK, gin.H{
			"message":  err,
			"puzzleId": puzzleId,
			"code":     4,
		})
		return
	}
	if responseResult["success"].(bool) == true {
		imgBase64 := responseResult["imgBase64"].(string)
		grayscale := convertToGrayScale(imgBase64)
		s := jisuan(grayscale)
		c.JSON(http.StatusOK, gin.H{
			"message":  "Data inserted successfully",
			"data":     s,
			"puzzleId": puzzleId,
			"code":     0,
		})

	}
	return
}

func convertToGrayScale(imgBase64 string) string {
	// 解码 Base64
	imgData, err := base64.StdEncoding.DecodeString(imgBase64)
	if err != nil {
		log.Printf("解码 Base64 失败: %v", err)
	}

	// 解码图像（支持自动检测格式）
	img, _, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		log.Printf("解码图像失败: %v", err)
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
		log.Printf("编码灰度图像失败: %v", err)
	}

	// 将 JPEG 编码的数据转换为 Base64
	grayBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	// 返回新的 Base64 编码字符串，带上前缀 "data:image/jpeg;base64,"
	return grayBase64
}
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
		log.Printf("序列化JSON失败: %v", err)
	}

	// 发送POST请求
	//resp, err := http.Post("http://127.0.0.1:1224/api/ocr", "application/json", bytes.NewBuffer(bodyJSON))
	resp, err := http.Post("http://107.148.176.146:1224/api/ocr", "application/json", bytes.NewBuffer(bodyJSON))
	if err != nil {
		log.Printf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 解析响应
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("解析响应失败: %v", err)
		return ""
	}

	// 格式化表达式，确保运算符前后有空格
	//re := regexp.MustCompile(`([+\-*/])`)
	//trim = re.ReplaceAllString(trim, " $1 ")

	// 计算表达式结果
	//v := evaluateExpression(trim)

	data := result["data"].(string)
	trim := strings.TrimSpace(data)
	return trim
}
