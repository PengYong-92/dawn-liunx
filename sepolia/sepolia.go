package main

import (
	"blockmesh/solver"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	Green        = "\033[32m"
	Reset        = "\033[0m"
	TOKEN        = "cfcd208495d565ef66e7dff9f98764da-8bb56c77b9dded9f82d6b9ccc6dde965-ae26fe5b4ce38925e6f13a7167fed3ea"
	BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
	//  BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAAGeVvgEAAAAA3RzAhyvIDr0%2BZWuNdzEwi3pET1U%3DAdNxDHxkTBjv1jVXPy3djIrX7lTcZTheBW4oFrQVLTLg6vjuGV"
	//BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
	//inviteCode = "91766401"
)

var tokenMap sync.Map

// 设置共享 map 中的值，确保值是 string 类型
func setValue(key string, value string) {
	tokenMap.Store(key, value)
}

// 获取共享 map 中的值，确保值是 string 类型
func getValue(key string) (string, bool) {
	value, ok := tokenMap.Load(key)
	if !ok {
		return "", false
	}
	strValue, ok := value.(string)
	return strValue, ok
}

type Config struct {
	Proxy      string `json:"proxy"`
	TokenFile  string `json:"sepoliaTokenfile"`
	InviteCode string `json:"inviteCode"`
}

func loadConfig(configFile string) (*Config, error) {
	// 获取当前工作目录
	currentDir, _ := os.Getwd()
	log.Printf("当前工作目录: %s\n", currentDir)
	config := &Config{}
	file, err := ioutil.ReadFile(fmt.Sprintf("%s%s%s", currentDir, string(filepath.Separator), configFile))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(file, config)
	return config, err
}

type RunBath struct {
	TokenFile  *os.File
	Client     *http.Client
	InviteCode string
}

type TwitterClient struct {
	AuthToken string
	Headers   http.Header
}
type Client struct {
	HttpClient *http.Client
	AuthToken  string
}

func runBath(runBath *RunBath) {
	tokens := []string{}
	scanner := bufio.NewScanner(runBath.TokenFile)
	for scanner.Scan() {
		tokens = append(tokens, scanner.Text())
	}
	//rand.Seed(time.Now().UnixNano()) // 设置随机种子

	for _, line := range tokens {
		lines := strings.Split(line, "-")
		// 确保分割得到的部分数量符合预期
		if len(lines) != 2 {
			fmt.Println("字符串格式不正确")
			return
		}
		// 提取分割后的部分
		token := lines[0]
		wallet := lines[1]
		// 打印结果
		fmt.Printf("token : %s\n", token)
		fmt.Printf("wallet : %s\n", wallet)
		twitterClient := &TwitterClient{
			AuthToken: token,
			Headers:   http.Header{},
		}
		twitterClient.Headers.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
		twitterClient.Headers.Set("HOST", "x.com")
		twitterClient.Headers.Set("x-twitter-active-user", "yes")
		twitterClient.Headers.Set("Origin", "https://x.com")
		twitterClient.Headers.Set("Authorization", "Bearer "+BEARER_TOKEN)
		// 关注
		twitterClient.follow("612865855", "", runBath.TokenFile)
		log.Println(Green + "关注成功" + Reset)
		time.Sleep(1 * time.Second)
		// 发推文
		// 定义参数
		formattedTweetText := fmt.Sprintf("@faucet_trade send ETH tokens to \n%s \n#sepolia_eth #sepolia #faucet #seth \nhttps://faucet.trade", "0x829B93414F54bEC1b404F5610B31f2551749745E")
		createTweetUrl := "https://x.com/i/api/graphql/xT36w0XM3A8jDynpkram2A/CreateTweet"

		// 调用 createTweet 函数
		twitterClient.createTweet(formattedTweetText, createTweetUrl, "")
		// 领水
		apikey := "CAP-C7314376D9418C07CF7CB36FEBF1C62B"
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
		defer cancel()

		var captcha string
		const maxRetries = 3
		for i := 0; i < maxRetries; i++ {
			res, err := solver.CapSolver(ctx, apikey, map[string]any{
				"type":       "ReCaptchaV2TaskProxyLess",
				"websiteURL": "https://faucet.trade/sepolia-eth-faucet/",
				"websiteKey": "6Le23gsmAAAAANaZGCoM1xNIJv3NAim2LTKoXWNN",
			})
			if err == nil {
				captcha = res.Solution["gRecaptchaResponse"].(string)
				fmt.Println("SUCCESS captcha")
				break
			}

			log.Printf("solver.CapSolver 调用失败: %v", err)
			if i < maxRetries-1 {
				log.Printf("重试 %d/%d", i+1, maxRetries)
				time.Sleep(time.Second * 2) // 等待一段时间再重试
			} else {
				log.Printf("重试次数已用尽")
				return
			}
		}

		// 要解析的URL
		url := "https://x.com/wsmxq63764515/status/1833393828163924231"

		// 截取 'x.com/' 后面的部分
		start := strings.Index(url, "x.com/")
		if start == -1 {
			fmt.Println("URL不正确，未找到 x.com/")
			return
		}

		// 找到 x.com/ 后面的部分
		path := url[start+len("x.com/"):]

		// 以 '/' 分割字符串
		parts := strings.Split(path, "/")
		var twitterUsername string
		var restid string
		// 用户名就是第一个部分
		if len(parts) > 0 {
			twitterUsername = parts[0]
			fmt.Println("twitterUsername:", twitterUsername)
			restid = parts[2]
			fmt.Println("restid:", restid)
		} else {
			fmt.Println("未找到用户名")
		}

		// 设置请求体内容
		recaptcha := captcha
		jsonRequestBody := fmt.Sprintf(`{
		"recaptcha": "%s",
		"wallet_address": "%s",
		"type": "sepolia_eth",
		"tweet_url": "https://x.com/%s/status/%s",
		"twitter_user_id": 0,
		"twitter_username": "%s"
	}`, recaptcha, wallet, twitterUsername, restid, twitterUsername)
		fmt.Println("jsonRequestBody:", jsonRequestBody)
		// 创建一个新的 POST 请求
		req, err := http.NewRequest("POST", "https://faucet.trade/api/faucet_form.php", bytes.NewBuffer([]byte(jsonRequestBody)))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		// 设置请求头
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", "_ga=GA1.1.1572546754.1725617169; _ga_5PJC9MX1WW=GS1.1.1725687470.2.1.1725687929.0.0.0")
		req.Header.Set("Origin", "https://faucet.trade")
		req.Header.Set("Referer", "https://faucet.trade/sepolia-eth-faucet")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
		req.Header.Set("sec-ch-ua", "\"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"128\"")
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("sec-ch-ua-platform", "\"Windows\"")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("failed to execute request: %v", err)
			return
		}
		defer resp.Body.Close()

		var body []byte

		// 检查 Content-Encoding 是否是 gzip
		if resp.Header.Get("Content-Encoding") == "gzip" {
			gzReader, err := gzip.NewReader(resp.Body)
			if err != nil {
				log.Printf("failed to create gzip reader: %v", err)
				return
			}
			defer gzReader.Close()

			// 读取解压后的数据
			body, err = io.ReadAll(gzReader)
			if err != nil {
				log.Printf("failed to read gzipped response body: %v", err)
				return
			}
		} else {
			// 非压缩响应体，直接读取
			body, err = io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("failed to read response body: %v", err)
				return
			}
		}

		log.Printf("获取账号授权参数: %s", body)
		// 打印响应状态码
		log.Printf("获取账号授权StatusCode: %s", resp.Status)

		// 检查响应状态码是否为 200
		if resp.StatusCode == http.StatusOK {
			log.Printf("领水请求成功")

			// 解码响应体内容
			if len(body) > 200 {
				// 将响应转换为字符串
				responseStr := string(body)

				// 匹配领水金额 <b> 标签中的内容
				re := regexp.MustCompile(`<b>(.*?)<\/b>`)
				match := re.FindStringSubmatch(responseStr)

				if len(match) > 1 {
					// 提取到的领水金额
					amount := match[1]
					log.Printf("领水成功，金额为: %s Sepolia ETH", amount)
				} else {
					log.Printf("未找到领水金额")
				}
			} else {
				log.Printf("响应内容太短，无法解析")
			}
		} else {
			log.Printf("领水请求失败，StatusCode: %d", resp.StatusCode)
		}
	}
}

// encode 使用AES CBC模式加密字符串，并返回十六进制编码的结果
func encode(info string) string {
	token, _ := getValue("token")
	// 从token中提取16字节的key
	key := []byte(token[:16])
	// 创建AES加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	// 填充数据
	paddedText := pad([]byte(info), aes.BlockSize)
	// 使用AES CBC模式加密
	iv := key // 在实际应用中，IV应该是独立的并且不同于key
	if len(iv) != aes.BlockSize {
		return ""
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(paddedText))
	mode.CryptBlocks(encrypted, paddedText)

	// 将加密结果转换为十六进制字符串
	return hex.EncodeToString(encrypted)
}

// pad 使用PKCS5填充数据
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	paddedData := make([]byte, len(data)+padding)
	copy(paddedData, data)
	for i := len(data); i < len(paddedData); i++ {
		paddedData[i] = byte(padding)
	}
	return paddedData
}

func decode(info string) (string, error) {
	token, _ := getValue("token")
	// 从 Authorization 头部提取 16 位的解密密钥
	tokenParts := strings.Split(token, "-")
	if len(tokenParts) < 3 {
		return "", fmt.Errorf("token does not contain enough parts")
	}
	decodeKey := tokenParts[2]
	if len(decodeKey) < 16 {
		return "", fmt.Errorf("token does not contain a valid key")
	}
	key := decodeKey[:16]

	// Decode the hex-encoded encrypted string
	ciphertext, err := hex.DecodeString(info)
	if err != nil {
		return "", err
	}

	// Create AES cipher
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// Create a new AES CBC mode decrypter
	iv := key // In CBC mode, the IV is typically set separately; here we use key as a placeholder
	if len(iv) != aes.BlockSize {
		return "", errors.New("IV length must be equal to block size")
	}
	mode := cipher.NewCBCDecrypter(block, []byte(iv))

	// Decrypt the data
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove PKCS5 padding
	paddingLen := int(ciphertext[len(ciphertext)-1])
	if paddingLen > len(ciphertext) {
		return "", errors.New("invalid padding length")
	}
	ciphertext = ciphertext[:len(ciphertext)-paddingLen]

	// Convert bytes to string and perform additional replacements
	result := strings.TrimSpace(string(ciphertext))
	result = strings.ReplaceAll(result, "\\u0026", "&")

	return result, nil
}
func sign(client *http.Client, t_token, invcode string) {
	log.Printf("登录token：%s", t_token)
	apikey := "CAP-C7314376D9418C07CF7CB36FEBF1C62B"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
	defer cancel()

	var captcha string
	var err error
	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {
		res, err := solver.CapSolver(ctx, apikey, map[string]any{
			"type":       "ReCaptchaV2TaskProxyLess",
			"websiteURL": "https://nebx.io",
			"websiteKey": "6LdTHTUqAAAAAL9L_93M7N5z_oeDIkeyfB_Ud3Y6",
		})
		if err == nil {
			captcha = res.Solution["gRecaptchaResponse"].(string)
			fmt.Println("SUCCESS captcha")
			break
		}

		log.Printf("solver.CapSolver 调用失败: %v", err)
		if i < maxRetries-1 {
			log.Printf("重试 %d/%d", i+1, maxRetries)
			time.Sleep(time.Second * 2) // 等待一段时间再重试
		} else {
			log.Printf("重试次数已用尽")
			return
		}
	}

	// 构建参数
	uuid := time.Now().UnixNano() / int64(time.Millisecond)
	param := map[string]interface{}{
		"googleCode": captcha,
		"uuid":       uuid,
	}
	jsonStr, err := json.Marshal(param)
	if err != nil {
		log.Printf("转换json错误: %v", err)
		return
	}

	// 构建请求
	s := encode(string(jsonStr))
	log.Printf("请求参数：%s", s)
	req, err := http.NewRequest("GET", "https://apiv1.nebx.io/login/xauth_url?sign="+s, nil)
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Origin", "https://nebx.io")
	req.Header.Set("Referer", "https://nebx.io/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36")
	req.Header.Set("Authorization", "Bearer "+TOKEN)

	// 发送请求并获取响应
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("failed to execute request: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read response body: %v", err)
		return
	}

	log.Printf("获取账号授权StatusCode: %s", resp.Status)
	log.Printf("获取账号授权参数: %s", body)

	if len(body) > 200 {
		var response map[string]interface{}
		decode, _ := decode(string(body))
		log.Printf("response: %s", decode)
		if err := json.Unmarshal([]byte(decode), &response); err != nil {
			log.Printf("failed to unmarshal response: %v", err)
			return
		}

		clientId, ok := response["clientId"].(string)
		if !ok {
			log.Printf("invalid clientId type")
			return
		}
		urls, ok := response["url"].(string)
		if !ok {
			log.Printf("invalid url type")
			return
		}

		state, _ := getParameterValue(urls, "state")
		log.Printf("state: %s", state)

		codeChallenge, _ := getParameterValue(urls, "code_challenge")
		log.Printf("code_challenge: %s", codeChallenge)
		log.Printf("clientId: %s", clientId)

		twitterResponse, err := twitter(clientId, state, codeChallenge, "", client, t_token)
		if err != nil {
			log.Printf("failed to authorize: %v", err)
			return
		}
		log.Printf("获取授权码: %s", twitterResponse)

		success, err, token := nebxLogin(invcode, state, twitterResponse, clientId, captcha, uuid, client)

		if success {
			setValue("token", token)
			log.Printf(Green + "登录成功" + Reset)
			client := &Client{
				HttpClient: client,
				AuthToken:  token,
			}
			time.Sleep(1000)
			success := client.check()
			if success {
				setValue("token", TOKEN)
			}
			log.Printf("检测积分是否成功: %v\n", success)
		}
	}
}

func getParameterValue(urlStr, parameterName string) (string, error) {
	// 编译正则表达式，用于匹配参数名和值
	pattern := regexp.MustCompile(parameterName + "=([^&]*)")
	// 查找匹配的部分
	matches := pattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		// 解码URL编码的参数值
		decodedValue, err := url.QueryUnescape(matches[1])
		if err != nil {
			return "", err
		}
		return decodedValue, nil
	}
	return "", nil
}

func twitter(clientId, state, codeChallenge, cookie string, client *http.Client, tToken string) (string, error) {
	baseURL := "https://twitter.com/i/api/2/oauth2/authorize"

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientId)
	params.Set("redirect_uri", "https://nebx.io/login")
	params.Set("scope", "tweet.read users.read follows.read")
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "plain")

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

	//fmt.Printf("%d : %s\n", status, ct0Cookie)
	if status == http.StatusOK {
		if authCode, ok := response["auth_code"].(string); ok {
			return authCode, nil
		}
	} else if code, ok := response["code"].(float64); ok && int(code) == 353 {
		//fmt.Printf("%s\n", response["message"].(string))
		time.Sleep(1000)
		auth, err := twitter(clientId, state, codeChallenge, ct0Cookie, client, tToken)
		if err != nil {
			return "", err
		}
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
func nebxLogin(inviteCode, state, twitter, clientId, capsolver string, uid int64, client *http.Client) (bool, error, string) {
	signIn := map[string]interface{}{
		"state":      state,
		"code":       twitter,
		"clientId":   clientId,
		"googleCode": capsolver,
		"inviteCode": inviteCode,
		"uuid":       uid,
	}

	data := url.Values{}
	data.Set("sign", encode(toJSON(signIn)))

	req, err := http.NewRequest("POST", "https://apiv1.nebx.io/login/sign_in", strings.NewReader(data.Encode()))
	if err != nil {
		return false, err, ""
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Origin", "https://nebx.io")
	req.Header.Set("Referer", "https://nebx.io/")
	req.Header.Set("Authorization", "Bearer "+TOKEN)

	resp, err := client.Do(req)
	if err != nil {
		return false, err, ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err, ""
	}

	status := resp.StatusCode
	bodyStr := string(body)
	fmt.Printf("nebxLogin status: %d\n", status)
	fmt.Printf("nebxLogin response: %s\n", bodyStr)

	if bodyStr == "too many request" {
		time.Sleep(5 * time.Second)
		return nebxLogin(inviteCode, state, twitter, clientId, capsolver, uid, client)
	}
	if len(bodyStr) > 200 {
		de, _ := decode(bodyStr)
		var decodedData map[string]interface{}
		// 将解密后的响应体解析为 JSON
		err = json.Unmarshal([]byte(de), &decodedData)
		if err != nil {
			log.Printf("解析 JSON 失败")
			return false, err, ""
		}

		// 获取 token 的值
		if token, ok := decodedData["token"].(string); ok {
			log.Printf("Token: %s", token)
			// 如果需要返回 token
			return true, err, token
		} else {
			log.Printf("响应中未找到 token 字段")
		}
	}

	return false, err, ""
}

func toJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func (t *TwitterClient) follow(userID, ct0 string, olTokenfile *os.File) (bool, float64) {

	log.Printf("%s  处理账户ID", userID)
	baseURL := "https://twitter.com/i/api/1.1/friendships/create.json"

	params := url.Values{}
	params.Set("include_profile_interstitial_type", "1")
	params.Set("include_blocking", "1")
	params.Set("include_blocked_by", "1")
	params.Set("include_followed_by", "1")
	params.Set("include_want_retweets", "1")
	params.Set("include_mute_edge", "1")
	params.Set("include_can_dm", "1")
	params.Set("include_can_media_tag", "1")
	params.Set("include_ext_is_blue_verified", "1")
	params.Set("include_ext_verified_type", "1")
	params.Set("include_ext_profile_image_shape", "1")
	params.Set("skip_status", "1")
	params.Set("user_id", userID)

	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())
	req, err := http.NewRequest("POST", fullURL, nil)
	if err != nil {
		log.Printf("failed to create request: %s", err)
		return false, 0
	}

	req.Header = t.Headers
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: t.AuthToken})
	if ct0 != "" {
		req.AddCookie(&http.Cookie{Name: "ct0", Value: ct0})
	}
	clients := &http.Client{}
	res, err := clients.Do(req)
	if err != nil {
		log.Printf("request failed: %s", err)
		return false, 0
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("failed to read response body: %s", err)
		return false, 0
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("failed to parse JSON: %s", err)
		return false, 0
	}

	if res.StatusCode == 200 {
		log.Printf(Green+"关注回参：%s"+Reset, toJSON(response))
		count := response["followers_count"].(float64)
		log.Printf(Green+"当前关注人数：%f"+Reset, count)
		if count > 8 {
			log.Printf(Green+"关注达标：%f"+Reset, count)
			return true, count
		}
		i := response["following"].(bool)
		if !i {
			return true, count
		}

	}

	if errors, ok := response["errors"].([]interface{}); ok && len(errors) > 0 {
		errorCode := int(errors[0].(map[string]interface{})["code"].(float64))
		switch errorCode {
		case 353:
			for _, cookie := range res.Cookies() {
				if cookie.Name == "ct0" {
					t.Headers.Set("x-csrf-token", cookie.Value)
					return t.follow(userID, cookie.Value, olTokenfile)
				}
			}
			return false, 0
		case 32, 64:
			log.Printf("%s  账号被封: %d", t.AuthToken, errorCode)
			removeLineFromFile(olTokenfile.Name(), t.AuthToken)
			return false, 0
		case 326:
			log.Printf("%s  账号被锁定: %d", t.AuthToken, errorCode)
			removeLineFromFile(olTokenfile.Name(), t.AuthToken)
			return false, 0
		case 344:
			log.Printf("%s  账号关注限制: %d", t.AuthToken, errorCode)
			removeLineFromFile(olTokenfile.Name(), t.AuthToken)
			return false, 0
		default:
			log.Printf("%s  账号关注失败: %d", t.AuthToken, errorCode)
			return false, 0
		}
	}

	return false, 0
}

type TweetResponse struct {
	Data struct {
		CreateTweet struct {
			TweetResults struct {
				Result struct {
					RestID string `json:"rest_id"`
				} `json:"result"`
			} `json:"tweet_results"`
		} `json:"create_tweet"`
	} `json:"data"`
}

// 发推文CreateTweet
// 定义一个创建推文的函数，接收 tweetText、url 和 queryId 作为参数
func (t *TwitterClient) createTweet(tweetText, url, ct0 string) (bool, string) {
	// 定义请求体，动态使用传入的 tweetText 和 queryId
	reqBody := fmt.Sprintf(`{
		"variables": {
			"tweet_text": "%s",
			"dark_request": false,
			"media": {"media_entities": [], "possibly_sensitive": false},
			"semantic_annotation_ids": [],
			"disallowed_reply_options": null
		},
		"features": {
			"communities_web_enable_tweet_community_results_fetch": true,
			"c9s_tweet_anatomy_moderator_badge_enabled": true,
			"responsive_web_edit_tweet_api_enabled": true,
			"graphql_is_translatable_rweb_tweet_is_translatable_enabled": true,
			"view_counts_everywhere_api_enabled": true,
			"longform_notetweets_consumption_enabled": true,
			"responsive_web_twitter_article_tweet_consumption_enabled": true,
			"tweet_awards_web_tipping_enabled": false,
			"creator_subscriptions_quote_tweet_preview_enabled": false,
			"longform_notetweets_rich_text_read_enabled": true,
			"longform_notetweets_inline_media_enabled": true,
			"articles_preview_enabled": true,
			"rweb_video_timestamps_enabled": true,
			"rweb_tipjar_consumption_enabled": true,
			"responsive_web_graphql_exclude_directive_enabled": true,
			"verified_phone_label_enabled": false,
			"freedom_of_speech_not_reach_fetch_enabled": true,
			"standardized_nudges_misinfo": true,
			"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
			"responsive_web_graphql_skip_user_profile_image_extensions_enabled": false,
			"responsive_web_graphql_timeline_navigation_enabled": true,
			"responsive_web_enhance_cards_enabled": false
		},
		"queryId": "xT36w0XM3A8jDynpkram2A"
	}`, tweetText)

	log.Printf("createTweet reqBody:", toJSON(reqBody))
	// 创建POST请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}

	req.Header = t.Headers
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: t.AuthToken})
	if ct0 != "" {
		req.AddCookie(&http.Cookie{Name: "ct0", Value: ct0})
	}
	// 发送请求
	clients := &http.Client{}
	res, err := clients.Do(req)
	log.Printf("res：%s", toJSON(res))

	if err != nil {
		log.Printf("request failed: %s", err)
		//return false, 0
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("failed to read response body: %s", err)
		//return false, 0
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("failed to parse JSON: %s", err)
		//return false, 0
	}
	// 解析响应体中的rest_id
	var tweetResp TweetResponse
	if err := json.Unmarshal(body, &tweetResp); err != nil {
		log.Fatalf("failed to unmarshal response: %v", err)
	}
	// 打印rest_id
	log.Printf("Tweet created successfully, rest_id: %s", tweetResp.Data.CreateTweet.TweetResults.Result.RestID)

	if res.StatusCode == 200 {
		log.Printf(Green+"发文回参：%s"+Reset, toJSON(response))
		return true, tweetResp.Data.CreateTweet.TweetResults.Result.RestID
	}
	if errors, ok := response["errors"].([]interface{}); ok && len(errors) > 0 {
		log.Printf("详细错误信息: %v", toJSON(errors))
	}

	if errors, ok := response["errors"].([]interface{}); ok && len(errors) > 0 {
		errorCode := int(errors[0].(map[string]interface{})["code"].(float64))
		log.Printf("发文回参errorCode：", errorCode)
		switch errorCode {
		case 353:
			for _, cookie := range res.Cookies() {
				if cookie.Name == "ct0" {
					t.Headers.Set("x-csrf-token", cookie.Value)
					return t.createTweet(tweetText, url, cookie.Value)
				}
			}
			return false, ""
		case 32, 64:
			log.Printf("%s  账号被封: %d", t.AuthToken, errorCode)
			//removeLineFromFile(olTokenfile.Name(), t.AuthToken)
			return false, ""
		case 326:
			log.Printf("%s  账号被锁定: %d", t.AuthToken, errorCode)
			//removeLineFromFile(olTokenfile.Name(), t.AuthToken)
			return false, ""
		case 344:
			log.Printf("%s  账号关注限制: %d", t.AuthToken, errorCode)
			//removeLineFromFile(olTokenfile.Name(), t.AuthToken)
			return false, ""
		default:
			log.Printf("%s  账号发文失败: %d", t.AuthToken, errorCode)
			return false, ""
		}
	}

	return false, ""
}

// 删除文件中特定行的函数
func removeLineFromFile(olTokenfile, lineToRemove string) error {
	// 读取文件的所有行
	input, err := ioutil.ReadFile(olTokenfile)
	if err != nil {
		return err
	}

	lines := strings.Split(string(input), "\n")
	var output []string

	for _, line := range lines {
		if strings.TrimSpace(line) != strings.TrimSpace(lineToRemove) {
			output = append(output, line)
		}
	}

	// 将过滤后的内容写回文件
	err = ioutil.WriteFile(olTokenfile, []byte(strings.Join(output, "\n")), 0644)
	if err != nil {
		return err
	}

	return nil
}
func (c *Client) check() bool {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("%s 登检测积分异常：%v", c.AuthToken, r)
		}
	}()

	// 生成 UUID
	uuid := time.Now().UnixNano() / int64(time.Millisecond)
	info := map[string]interface{}{
		"uuid": uuid,
	}
	// 将 info 转换为 JSON 字符串
	baseUrl := "https://apiv1.nebx.io/user/check"
	params := url.Values{}
	params.Set("sign", encode(toJSON(info)))
	fullURL := fmt.Sprintf("%s?%s", baseUrl, params.Encode())
	// 发送 POST 请求
	req, err := http.NewRequest("POST", fullURL, nil)
	if err != nil {
		log.Printf("%s 创建请求失败: %v", c.AuthToken, err)
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Origin", "https://nebx.io")
	req.Header.Set("Referer", "https://nebx.io/")
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		log.Printf("%s 请求失败: %v", c.AuthToken, err)
		return false
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("%s 读取响应失败: %v", c.AuthToken, err)
		return false
	}

	if len(body) > 200 {
		var decodedData map[string]interface{}

		// 先解密响应体
		decryptedBody, err := decode(string(body))
		if err != nil {
			log.Printf("%s 解密响应失败: %v", c.AuthToken, err)
			return false
		}

		// 将解密后的响应体解析为 JSON
		err = json.Unmarshal([]byte(decryptedBody), &decodedData)
		if err != nil {
			log.Printf("%s 解析 JSON 失败: %v", c.AuthToken, err)
			return false
		}
		log.Printf("解析 JSON : %s", toJSON(&decodedData))
		// 提取并记录积分信息
		if score, ok := decodedData["score"].(float64); ok {
			log.Printf(Green+"积分: %v", score)
			return true
		}

		log.Printf("%s 响应中未找到积分字段", c.AuthToken)
	} else {
		log.Printf("%s 响应体长度不足，可能请求失败", c.AuthToken)
	}

	log.Printf("%s 检测积分失败===网页返回错误 %d %s", c.AuthToken, resp.StatusCode, string(body))
	return false
}

func main() {
	os.Setenv("http_proxy", "http://172.16.100.237:7899")
	os.Setenv("https_proxy", "http://172.16.100.237:7899")
	// 使用 flag 包处理命令行参数
	configPath := flag.String("config", "config.json", "配置文件的路径")
	flag.Parse()
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}
	proxy, err := url.Parse(config.Proxy)
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

	tokenFile, err := os.Open(config.TokenFile)
	if err != nil {
		log.Fatalf("打开 tokenFile 文件失败: %v", err)
	}
	defer tokenFile.Close()
	//
	//newTokenFile, err := os.Open(config.NewTokenFile)
	//if err != nil {
	//	log.Fatalf("打开新 newTokenFile 文件失败: %v", err)
	//}
	//defer newTokenFile.Close()

	setValue("token", TOKEN)
	runbath := &RunBath{
		TokenFile:  tokenFile,
		Client:     client,
		InviteCode: config.InviteCode,
	}
	runBath(runbath)
}
