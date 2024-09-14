package main

import (
	"bufio"
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func main() {
	password := "r9452tkHWVqdfL9ifknw7K0PReRAf" // 固定密码
	username := "root"
	port := "22"

	// 打开文件
	file, err := os.Open("D:\\money\\Dawn-main\\deployment\\ocean\\zhanghao.txt")
	if err != nil {
		fmt.Println("读取文件失败:", err)
		return
	}
	defer file.Close()

	var wg sync.WaitGroup

	// 逐行读取文件
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 将每行按照逗号分割
		fields := strings.Split(line, ",")
		if len(fields) != 3 {
			log.Printf("文件格式不正确: %v", line)
			saveFailedIP(line)
			continue
		}
		// 获取每行的 IP、私钥和管理员账号
		ip := fields[0]
		privateKey := fields[2]
		allowedAdmins := fields[1]
		log.Printf("处理服务器：%s", ip)

		// 为每个 IP 启动一个 goroutine 来处理
		wg.Add(1)
		go func(ip, privateKey, allowedAdmins string) {
			defer wg.Done()
			processServer(ip, password, username, port, privateKey, allowedAdmins)
		}(ip, privateKey, allowedAdmins)
	}

	// 等待所有 goroutines 完成
	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Println("读取文件过程中出错:", err)
	}
}

// 处理每个服务器的逻辑
func processServer(ip, password, username, port, privateKey, allowedAdmins string) {
	// 建立 SSH 连接
	client, err := connectSSH(ip, password, username, port)
	if err != nil {
		log.Printf("SSH 连接失败: %v", err)
		saveFailedIP(ip)
		return
	}
	defer client.Close()

	// 步骤 1: 检查并创建 ocean 目录
	err = checkOrCreateDirectory(client, "~/ocean")
	if err != nil {
		saveFailedIP(ip)
		return
	}

	// 步骤 2: 上传 docker-compose.yml 文件
	err = uploadFile(client, "D:\\money\\Dawn-main\\deployment\\ocean\\docker-compose.yml", "/root/ocean/docker-compose.yml")
	if err != nil {
		fmt.Println("文件上传失败:", err)
		saveFailedIP(ip)
		return
	}

	// 步骤 3: 获取服务器外网 IP
	externalIP := getExternalIP(client)

	// 步骤 4, 5: 替换 docker-compose.yml 文件中的占位符
	replaceFileContent(client, externalIP, privateKey, allowedAdmins)

	// 步骤 6: 异步执行 docker compose up -d
	err = executeDockerCompose(client)
	if err != nil {
		saveFailedIP(ip)
		return
	}
}

// 保存失败的 IP 到 txt 文件
func saveFailedIP(ip string) {
	file, err := os.OpenFile("failed_ips.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("无法打开或创建文件: %v", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(ip + "\n"); err != nil {
		log.Printf("无法写入文件: %v", err)
	}
}

// 建立 SSH 连接
func connectSSH(ip, password, username, port string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", ip+":"+port, config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// 检查并创建目录
func checkOrCreateDirectory(client *ssh.Client, dirPath string) error {
	session, err := client.NewSession()
	if err != nil {
		fmt.Println("创建 SSH 会话失败:", err)
		return err
	}
	defer session.Close()

	cmd := fmt.Sprintf("mkdir -p %s", dirPath)
	err = session.Run(cmd)
	if err != nil {
		return err
	}
	return nil
}

// 上传文件
func uploadFile(client *ssh.Client, localPath, remotePath string) error {
	// 创建 SFTP 客户端
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("创建SFTP客户端失败: %v", err)
	}
	defer sftpClient.Close()

	// 检查本地文件是否存在
	srcFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("本地文件打开失败: %v", err)
	}
	defer srcFile.Close()

	// 获取远程文件的目录部分
	remoteDir := filepath.Dir(remotePath)

	// 尝试创建远程目录
	err = sftpClient.MkdirAll(remoteDir)
	if err != nil {
		return fmt.Errorf("远程目录创建失败: %v", err)
	}

	// 在远程路径上创建文件
	dstFile, err := sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("远程文件创建失败: %v", err)
	}
	defer dstFile.Close()

	// 复制文件内容到远程文件
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("文件复制失败: %v", err)
	}

	log.Printf("文件上传成功: %s -> %s\n", localPath, remotePath)
	return nil
}

// 获取服务器外网 IP
func getExternalIP(client *ssh.Client) string {
	session, _ := client.NewSession()
	defer session.Close()
	ipBytes, _ := session.CombinedOutput("curl -s http://checkip.amazonaws.com")
	return strings.TrimSpace(string(ipBytes))
}

// 替换文件中的占位符
func replaceFileContent(client *ssh.Client, externalIP, privateKey, allowedAdmins string) {
	session, _ := client.NewSession()
	defer session.Close()

	cmd := fmt.Sprintf(`
		sed -i "s|P2P_ANNOUNCE_ADDRESSES: .*|P2P_ANNOUNCE_ADDRESSES: '[\"/ip4/%s/tcp/19000\", \"/ip4/%s/ws/tcp/19001\"]'|" /root/ocean/docker-compose.yml &&
		sed -i 's/PRIVATE_KEY: .*/PRIVATE_KEY: '%s'/' /root/ocean/docker-compose.yml &&
		sed -i "s|ALLOWED_ADMINS: .*|ALLOWED_ADMINS: '[\"%s\"]'|" /root/ocean/docker-compose.yml
	`, externalIP, externalIP, privateKey, allowedAdmins)
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

	err := session.Run("cd /root/ocean && docker compose down -v && docker compose up -d &")
	if err != nil {
		return err
	}
	log.Printf("启动命令执行成功")
	return nil
}
