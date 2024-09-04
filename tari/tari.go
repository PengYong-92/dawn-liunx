package main

import (
	"blockmesh/solver"
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	PROXY_URL    = "http://2892ED58F5DF1579-residential-country_US-r_0m-s_PDfBsmnJTM:Qbb645Mf@gw-us.nstproxy.com:24125"
	BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
	Green        = "\033[32m"
	Reset        = "\033[0m"
)

func login(client *http.Client, referralCode string) (string, []*http.Cookie) {

	captcha := getCaptcha()
	if captcha == "" {
		log.Printf("获取验证码失败")
		return "", nil
	}
	baseUrl := "https://rwa.y.at/auth/twitter"
	params := url.Values{}
	params.Set("quest", "code")
	params.Set("token", captcha)
	params.Set("referralCode", referralCode)
	fullURL := fmt.Sprintf("%s?%s", baseUrl, params.Encode())

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		log.Printf("初始化失败：%s", baseUrl)
		return "", nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36")
	req.Header.Set("Referer", "https://airdrop.tari.com/")
	req.Header.Set("HOST", "rwa.y.at")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "zh-CN")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// 禁止自动重定向
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("初始化失败：%s", baseUrl)
		return "", nil
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取body失败: %v", err)
		return "", nil
	}

	if 302 == resp.StatusCode {
		location := resp.Header.Get("Location")
		log.Printf("获取Location：%s", location)
		if len(location) > 20 {
			oauthToken, _ := getParameterValue(location, "oauth_token")
			log.Printf("获取的oauth_token: %s", oauthToken)

			return oauthToken, resp.Cookies()
		}
	}
	return "", nil
}

/*func getTwtterAuthCode1(oauthToken, authToken string) string {

	baseUrl := "https://api.twitter.com/oauth/authenticate"
	params := url.Values{}
	params.Set("oauth_token", oauthToken)
	fullURL := fmt.Sprintf("%s?%s", baseUrl, params.Encode())

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		log.Printf("初始化失败：%s", baseUrl)
	}
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: authToken})
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("请求失败：%s", baseUrl)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("%s 推特授权异常：%v", authToken, err)
	}
	//log.Println(string(body))
	for _, cookie := range resp.Cookies() {
		log.Printf("getTwtterAuthCode1 Cookie: %s = %s", cookie.Name, cookie.Value)
		if "ct0" == cookie.Name {
			log.Println("添加ct0后重试")
			//getTwtterAuthCode(oauthToken, authToken, cookie.Name)
		}
	}

	//// 定义正则表达式来匹配 authenticity_token 的 value
	//re := regexp.MustCompile(`<input[^>]*name="authenticity_token"[^>]*value="([^"]+)"`)
	//matches := re.FindStringSubmatch(string(body))
	//if len(matches) > 1 {
	//	// 第一个匹配是整个模式，第二个是 value 值
	//	authenticityToken := matches[1]
	//	log.Printf("authenticity_token 的 value: %s\n", authenticityToken)
	//	return authenticityToken
	//} else {
	//	log.Println("未找到 authenticity_token")
	//}
	return ""
}*/

func getTwtterAuthCode(oauthToken, authToken string) (string, []*http.Cookie) {

	baseUrl := "https://api.x.com/oauth/authenticate"
	params := url.Values{}
	params.Set("oauth_token", oauthToken)
	fullURL := fmt.Sprintf("%s?%s", baseUrl, params.Encode())

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		log.Printf("初始化失败：%s", baseUrl)
		return "", nil
	}
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: authToken})
	//req.Header.Set("x-csrf-token", ct0)
	//req.AddCookie(&http.Cookie{Name: "ct0", Value: ct0})
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("请求失败：%s", baseUrl)
		return "", nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("%s 推特授权异常：%v", authToken, err)
		return "", nil
	}
	// 定义正则表达式来匹配 authenticity_token 的 value
	re := regexp.MustCompile(`<input[^>]*name="authenticity_token"[^>]*value="([^"]+)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		// 第一个匹配是整个模式，第二个是 value 值
		authenticityToken := matches[1]
		log.Printf("authenticity_token 的 value: %s\n", authenticityToken)
		return authenticityToken, resp.Cookies()
	} else {
		log.Println("未找到 authenticity_token")
	}
	return "", nil
}

func twitterAuthorize(authenticityToken, oauthToken, authToken string, cookie []*http.Cookie) string {
	// 构造 POST 请求的表单数据
	formData := url.Values{}
	formData.Set("authenticity_token", authenticityToken)
	formData.Set("redirect_after_login", "https://api.x.com/oauth/authorize?oauth_token="+oauthToken)
	formData.Set("oauth_token", oauthToken)

	// 创建 POST 请求
	encode := formData.Encode()
	req, err := http.NewRequest("POST", "https://api.x.com/oauth/authorize", strings.NewReader(encode))
	if err != nil {
		log.Printf("创建请求失败: %v", err)
		return ""
	}
	// 设置请求头
	req.Header.Set("Origin", "https://api.x.com")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+BEARER_TOKEN)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: authToken})

	for _, cookie := range cookie {
		req.AddCookie(cookie)
	}
	// 创建 HTTP 客户端并发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("twitterAuthorize 发送请求失败: %v", err)
		return ""
	}
	defer resp.Body.Close()
	// 读取网页内容
	bodyBytes, err := io.ReadAll(resp.Body)

	body := string(bodyBytes)

	log.Printf("twitterAuthorize 返回状态%v - %s", resp.StatusCode, resp.Status)
	// 使用正则表达式匹配 meta 标签并提取 oauth_verifier
	re := regexp.MustCompile(`<meta\s+http-equiv="refresh"\s+content="[^"]*oauth_verifier=([^"&]+)"`)
	matches := re.FindStringSubmatch(body)

	if len(matches) > 1 {
		oauthVerifier := matches[1]
		log.Printf("twitterAuthorize oauth_verifier: %s\n", oauthVerifier)
		return oauthVerifier
	} else {
		log.Println("twitterAuthorize 未找到 oauth_verifier")
	}
	return ""
}

func twitterCallback(oauthToken, Verifier string, client *http.Client, cookit []*http.Cookie) string {
	// 设置请求参数
	params := url.Values{}
	params.Set("oauth_token", oauthToken)
	params.Set("oauth_verifier", Verifier)

	// 设置请求头
	headers := http.Header{}
	headers.Set("Referer", "https://api.x.com/")
	headers.Set("HOST", "rwa.y.at")
	headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	headers.Set("Accept-Language", "zh-CN")
	// 构建请求 URL
	callbackURL := "https://rwa.y.at/auth/twitter/callback?" + params.Encode()
	//log.Println("twitterCallback req：" + callbackURL)
	// 构建 HTTP 请求
	req, err := http.NewRequest("GET", callbackURL, nil)
	if err != nil {
		log.Printf("创建请求失败: %v", err)
		return ""
	}
	req.Header = headers
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// 禁止自动重定向
		return http.ErrUseLastResponse
	}
	for _, cookie := range cookit {
		req.AddCookie(cookie)
	}
	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("请求失败: %v", err)
		return ""
	}
	defer resp.Body.Close()
	//body, err := io.ReadAll(resp.Body)
	//if err != nil {
	//	log.Printf("%s 推特授权异常：%v", oauthToken, err)
	//}
	//log.Printf("twitterCallback resp: %s", string(body))
	// 检查状态码，如果是302重定向
	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "token=") {
			token := strings.Split(strings.Split(location, "token=")[1], "&")[0]
			log.Printf("twitterCallback token: %s\n", token)
			return token
		}
	} else {
		log.Println("推特回调失败")
	}

	return ""
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
			"websiteURL": "https://airdrop.tari.com/quests",
			"websiteKey": "0x4AAAAAAAZjcPdX24N10Y-m",
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

type Response struct {
	Quests []Quest `json:"quests"`
	Status int     `json:"status"`
}
type Quest struct {
	Name      string `json:"name"`
	IsHidden  bool   `json:"isHidden"`
	IsExpired bool   `json:"isExpired"`
}

func quests(client *http.Client, token string) Response {
	var response Response
	response.Quests = make([]Quest, 1)
	req, err := http.NewRequest("GET", "https://airdrop.tari.com/api/quest/list-with-fulfillment", nil)
	if err != nil {
		log.Printf("创建请求失败: %v", err)
		return response
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		log.Printf("请求失败: %v", err)
		return response
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)

	if res.StatusCode == http.StatusOK {

		if err := json.Unmarshal(body, &response); err != nil {
			log.Printf("解析响应失败: %v", err)
			return response
		}
		response.Status = 0
		return response
		//for _, quest := range response.Quests {
		//	if !quest.IsHidden && !quest.IsExpired {
		//		name := quest.Name
		//		if !doTask(client, name, token) {
		//			return false
		//		}
		//	}
		//}
		//return response
	}

	log.Println("获取 quests 失败")
	return response
}

func doTask(client *http.Client, questName string, token string) {
	baseUrl := fmt.Sprintf("https://airdrop.tari.com/api/quest/verify/%s", questName)
	req, err := http.NewRequest("GET", baseUrl, nil)
	if err != nil {
		log.Printf("创建请求失败: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		log.Printf("请求失败: %v", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		var result map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
			log.Printf("解析响应失败: %v", err)
			return
		}
		if success, ok := result["success"].(bool); ok && success {
			log.Printf(Green+"完成任务 %s 成功"+Reset, questName)
			return
		}
	}
	log.Printf("完成任务 %s 失败", questName)
}

func toJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// removeAuthToken 从文件中删除指定的authToken行，并实时修改源文件
func removeAuthToken(tokenFilePath, authToken string) error {
	// 打开文件进行读取
	file, err := os.Open(tokenFilePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	var lines []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 如果当前行不是目标authToken，则保留该行
		if strings.TrimSpace(line) != authToken {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("扫描文件失败: %v", err)
	}

	// 重新打开文件用于写入
	file, err = os.OpenFile(tokenFilePath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("重新打开文件失败: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("写入文件失败: %v", err)
		}
	}

	// 刷新缓冲区并关闭文件
	writer.Flush()

	return nil
}
func main() {
	// 获取当前目录作为默认 tokenFilePath
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("获取当前目录失败: %v", err)
	}
	defaultTokenFilePath := filepath.Join(currentDir, "token.txt")
	log.Printf("默认token文件位置：%s\n", defaultTokenFilePath)

	proxyURL := flag.String("proxy", PROXY_URL, "代理 URL")
	tokenFilePath := flag.String("tokenfile", defaultTokenFilePath, "token文件位置")
	referralCode := flag.String("referralcode", "qSOPR4VMK8,AN6csZWQRr,WFmjZuKv2U,d8SoYNZKHk,h95p6oWS6R", "Referral Code")
	referralType := flag.Int("referralType", 1, "默认只刷邀请任务，需要全任务，输入0")

	flag.Parse()

	refCode := strings.Split(*referralCode, ",")
	refCodeLen := len(refCode)

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
	tokenFile, err := os.Open(*tokenFilePath)
	if err != nil {
		log.Fatalf("打开 tokenFile 文件失败: %v", err)
	}
	defer tokenFile.Close()

	var wg sync.WaitGroup // 创建一个 WaitGroup
	var conout = 0

	newScanner := bufio.NewScanner(tokenFile)
	for newScanner.Scan() {
		// 使用循环中的referral code
		loginReferralCode := refCode[conout%refCodeLen]

		authToken := newScanner.Text()
		accountParts := strings.Split(authToken, "----")
		if len(accountParts) > 5 {
			authToken = accountParts[len(accountParts)-5]
		}
		log.Printf(Green+"当前TOKEN：%s"+Reset, authToken)
		log.Printf(Green+"当前邀请码：%s"+Reset, loginReferralCode)
		//登录获取程序token
		oauthToken, loginCookies := login(client, loginReferralCode)
		if oauthToken == "" {
			removeAuthToken(*tokenFilePath, authToken)
			continue
		}
		//通过程序token获取登录账号的推特授权
		authenticityToken, cookies := getTwtterAuthCode(oauthToken, authToken)
		if authenticityToken == "" {
			removeAuthToken(*tokenFilePath, authToken)
			continue
		}
		////获取授权链接Token
		oauthVerifier := twitterAuthorize(authenticityToken, oauthToken, authToken, cookies)
		if oauthVerifier == "" {
			removeAuthToken(*tokenFilePath, authToken)
			continue
		}
		//获取项目token
		authorizationToken := twitterCallback(oauthToken, oauthVerifier, client, loginCookies)
		if authorizationToken == "" {
			removeAuthToken(*tokenFilePath, authToken)
			continue
		}
		//查询任务
		response := quests(client, authorizationToken)
		if 0 == response.Status {
			wg.Add(1) // 增加 WaitGroup 计数
			go func(authToken string) {
				defer wg.Done() // 任务完成时减少 WaitGroup 计数
				successTask(response, client, authorizationToken, *referralType)
			}(authToken)
		}
		removeAuthToken(*tokenFilePath, authToken)
		conout++
		time.Sleep(5 * time.Second)

		if conout >= 10 {
			fmt.Println("已经使用10个authToken")
		}
	}
	wg.Wait()
}

func successTask(response Response, client *http.Client, authorizationToken string, rtrpe int) {
	for _, quest := range response.Quests {
		if !quest.IsHidden && !quest.IsExpired {
			name := quest.Name
			if rtrpe == 1 && ("retweet-on-x-new-mandatory" == name || "follow-on-x" == name || "retweet-on-x" == name) {
				doTask(client, name, authorizationToken)
				time.Sleep(1 * time.Second)
			}
			if rtrpe == 2 {
				doTask(client, name, authorizationToken)
				time.Sleep(1 * time.Second)
			}
		}
	}
}
