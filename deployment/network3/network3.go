package main

import (
	"blockmesh/utils"
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"strings"
	"sync"
)

func main() {
	//os.Setenv("https_proxy", "http://172.16.111.3:7897")
	//os.Setenv("http_proxy", "http://172.16.111.3:7897")
	password := "r9452tkHWVqdfL9ifknw7K0PReRAf" // 固定密码
	username := "root"
	port := "22"

	// 打开文件
	file, err := os.Open("D:\\money\\Dawn-main\\deployment\\network3\\zhanghao.txt")
	if err != nil {
		fmt.Println("读取文件失败:", err)
		return
	}
	defer file.Close()

	var wg sync.WaitGroup

	// 逐行读取文件
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := scanner.Text()
		// 将每行按照逗号分割
		//fields := strings.Split(line, ",")
		//if len(fields) != 3 {
		//	log.Printf("文件格式不正确: %v", line)
		//	saveFailedIP(line)
		//	continue
		//}
		// 获取每行的 IP、私钥和管理员账号
		//ip := fields[0]
		log.Printf("处理服务器：%s", ip)

		// 为每个 IP 启动一个 goroutine 来处理
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			processServer(ip, password, username, port)
		}(ip)
	}

	// 等待所有 goroutines 完成
	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Println("读取文件过程中出错:", err)
	}
}

// 处理每个服务器的逻辑
func processServer(ip, password, username, port string) {
	// 建立 SSH 连接
	client, err := utils.ConnectSSH(ip, password, username, port)
	if err != nil {
		log.Printf("SSH 连接失败: %v", err)
		saveFailedIP(ip)
		return
	}
	defer client.Close()

	// 步骤 1: 检查并创建 ocean 目录
	err = utils.CheckOrCreateDirectory(client, "/root/network3")
	if err != nil {
		saveFailedIP(ip)
		return
	}

	// 步骤 2: 上传 docker-compose.yml 文件
	err = utils.UploadFile(client, "D:\\money\\Dawn-main\\deployment\\network3\\docker-compose.yml", "/root/network3/docker-compose.yml")
	if err != nil {
		fmt.Println("文件上传失败:", err)
		saveFailedIP(ip)
		return
	}

	// 步骤 3: 获取服务器外网 IP
	externalIP := getExternalIP(client)

	// 步骤 4, 5: 替换 docker-compose.yml 文件中的占位符
	replaceFileContent(client, externalIP)

	// 步骤 6: 异步执行 docker compose up -d
	err = executeDockerCompose(client)
	if err != nil {
		saveFailedIP(ip)
		return
	}
}

// 保存失败的 IP 到 txt 文件
func saveFailedIP(ip string) {
	file, err := os.OpenFile("failed_ips_network.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("无法打开或创建文件: %v", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(ip + "\n"); err != nil {
		log.Printf("无法写入文件: %v", err)
	}
}

// 获取服务器外网 IP
func getExternalIP(client *ssh.Client) string {
	session, _ := client.NewSession()
	defer session.Close()
	ipBytes, _ := session.CombinedOutput("curl -s http://checkip.amazonaws.com")
	return strings.TrimSpace(string(ipBytes))
}

// 替换文件中的占位符
func replaceFileContent(client *ssh.Client, externalIP string) {
	session, _ := client.NewSession()
	defer session.Close()

	//cmd := fmt.Sprintf(`sed -i "s|ADDRESS= .*|ADDRESS=%s|" /root/network3/docker-compose.yml`, externalIP)
	cmd := fmt.Sprintf(`sed -i "s|ADDRESS *= *.*|ADDRESS=%s|" /root/network3/docker-compose.yml`, externalIP)
	err := session.Run(cmd)
	if err != nil {
		log.Printf("替换 IP 地址失败: %v", err)
		return
	}
}

// 执行 docker compose up -d
func executeDockerCompose(client *ssh.Client) error {
	session, _ := client.NewSession()
	defer session.Close()

	err := session.Run("cd /root/network3 && docker compose down -v && docker compose up -d &")
	if err != nil {
		return err
	}
	log.Printf("启动命令执行成功")
	return nil
}
