package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
)

// SaveFailed 保存文件
func SaveFailed(str, filePath string) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("无法打开或创建文件: %v", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(str + "\n"); err != nil {
		log.Printf("无法写入文件: %v", err)
	}
}

// ToJSON 转换成json
func ToJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// 将剩余的地址重新写回文件
func WriteAddressesToFile(fileAddress string, addresses []string) error {
	file, err := os.OpenFile(fileAddress, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, address := range addresses {
		_, err := writer.WriteString(address + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

// 建立 SSH 连接
func ConnectSSH(ip, password, username, port string) (*ssh.Client, error) {
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
func CheckOrCreateDirectory(client *ssh.Client, dirPath string) error {
	session, err := client.NewSession()
	if err != nil {
		fmt.Println("创建 SSH 会话失败:", err)
		return err
	}
	defer session.Close()

	cmd := fmt.Sprintf("mkdir -p %s", dirPath)
	log.Printf("CMD: %s", cmd)
	err = session.Run(cmd)
	if err != nil {
		return err
	}
	return nil
}

// 上传文件
func UploadFile(client *ssh.Client, localPath, remotePath string) error {
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

func GetParameterValue(urlStr, parameterName string) (string, error) {
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
