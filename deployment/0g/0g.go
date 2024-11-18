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
	password := "r9452tkHWVqdfL9ifknw7K0PReRAf" // 固定密码
	username := "root"
	port := "22"

	// 打开文件
	file, err := os.Open("D:\\GoProject\\src\\dawn-liunx\\deployment\\0g\\zhanghao.txt")
	if err != nil {
		fmt.Println("读取文件失败:", err)
		return
	}
	defer file.Close()

	var wg sync.WaitGroup
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 将每行按照逗号分割
		fields := strings.Split(line, ",")
		if len(fields) != 2 {
			log.Printf("文件格式不正确: %v", line)
			continue
		}
		ip := fields[0]
		privateKey := fields[1]
		log.Printf("处理服务器：%s", ip)
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			processServer(ip, password, username, port, privateKey)
		}(ip)
	}
	// 等待所有 goroutines 完成
	wg.Wait()
	if err := scanner.Err(); err != nil {
		fmt.Println("读取文件过程中出错:", err)
	}
}

// 处理每个服务器的逻辑
func processServer(ip, password, username, port, privateKey string) {
	// 建立 SSH 连接
	client, err := utils.ConnectSSH(ip, password, username, port)
	if err != nil {
		log.Printf("SSH 连接失败: %v", err)
		return
	}
	defer client.Close()

	// 步骤 1: 检查并创建 ocean 目录
	err = utils.CheckOrCreateDirectory(client, "/root/0gdocker")
	if err != nil {
		return
	}

	// 步骤 2: 上传 docker-compose.yml 文件
	err = utils.UploadFile(client, "D:\\GoProject\\src\\dawn-liunx\\deployment\\0g\\docker-compose.yml", "/root/0gdocker/docker-compose.yml")
	_ = utils.UploadFile(client, "D:\\GoProject\\src\\dawn-liunx\\deployment\\0g\\log_config", "/root/0gdocker/log_config")
	_ = utils.UploadFile(client, "D:\\GoProject\\src\\dawn-liunx\\deployment\\0g\\config-testnet.toml", "/root/0gdocker/config-testnet.toml")
	if err != nil {
		fmt.Println("文件上传失败:", err)
		return
	}
	// 步骤 4, 5: 替换 docker-compose.yml 文件中的占位符
	replaceFileContent(client, privateKey)

	// 步骤 6: 异步执行 docker compose up -d
	err = executeDockerCompose(client)
	if err != nil {
		return
	}
}

// 替换文件中的占位符
func replaceFileContent(client *ssh.Client, externalIP string) {
	session, _ := client.NewSession()
	defer session.Close()

	//cmd := fmt.Sprintf(`sed -i "s|ADDRESS= .*|ADDRESS=%s|" /root/network3/docker-compose.yml`, externalIP)
	cmd := fmt.Sprintf(`sed -i "s|MINER_KEY *= *.*|MINER_KEY=%s|" /root/0gdocker/docker-compose.yml`, externalIP)
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

	err := session.Run("cd /root/0gdocker && docker compose down -v && docker compose up -d &")
	if err != nil {
		return err
	}
	log.Printf("启动命令执行成功")
	return nil
}
