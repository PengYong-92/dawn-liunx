package main

import (
	"blockmesh/utils"
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"sync"
)

func main() {
	password := "r9452tkHWVqdfL9ifknw7K0PReRAf" // 固定密码
	username := "root"
	port := "22"

	// 打开文件
	file, err := os.Open("D:\\GoProject\\src\\dawn-liunx\\deployment\\unichain\\ip.txt")
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
		// 获取每行的 IP、私钥和管理员账号
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
	err = utils.CheckOrCreateDirectory(client, "/root/uni-chain")
	if err != nil {
		saveFailedIP(ip)
		return
	}

	// 步骤 2: 上传 docker-compose.yml 文件
	if utils.UploadFile(client, "D:\\GoProject\\src\\dawn-liunx\\deployment\\unichain\\docker-compose.yml", "/root/uni-chain/docker-compose.yml") != nil {
		fmt.Println("文件上传失败:", err)
		saveFailedIP(ip)
		return
	}
	if utils.UploadFile(client, "D:\\GoProject\\src\\dawn-liunx\\deployment\\unichain\\.env", "/root/uni-chain/.env") != nil {
		fmt.Println("文件上传失败:", err)
		saveFailedIP(ip)
		return
	}
	if utils.UploadFile(client, "D:\\GoProject\\src\\dawn-liunx\\deployment\\unichain\\.env.sepolia", "/root/uni-chain/.env.sepolia") != nil {
		fmt.Println("文件上传失败:", err)
		saveFailedIP(ip)
		return
	}

	err = executeDockerCompose(client)
	if err != nil {
		saveFailedIP(ip)
		return
	}
}

// 保存失败的 IP 到 txt 文件
func saveFailedIP(ip string) {
	file, err := os.OpenFile("D:\\GoProject\\src\\dawn-liunx\\deployment\\unichain\\failed_ips_network.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("无法打开或创建文件: %v", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(ip + "\n"); err != nil {
		log.Printf("无法写入文件: %v", err)
	}
}

// 执行 docker compose up -d
func executeDockerCompose(client *ssh.Client) error {
	session, _ := client.NewSession()
	defer session.Close()

	err := session.Run("cd /root/uni-chain && docker compose down -v && docker compose up -d &")
	if err != nil {
		return err
	}
	log.Printf("启动命令执行成功")
	return nil
}
