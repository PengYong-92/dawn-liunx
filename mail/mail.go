package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"time"
)

const (
	serverIP          = "38.55.99.167"
	username          = "root"
	password          = "r9452tkHWVqdfL9ifknw7K0PReRAf"
	outputFile        = "emails.csv"
	defaultIterations = 10 // 默认循环次数
)

// 扩展的单词库
var wordList = []string{
	"apple", "banana", "cherry", "date", "elderberry",
	"fig", "grape", "honeydew", "kiwi", "lemon",
	"mango", "nectarine", "orange", "papaya", "quince",
	"raspberry", "strawberry", "tangerine", "ugli", "vanilla",
	"watermelon", "xigua", "yellow", "zucchini",
	"apricot", "blueberry", "cantaloupe", "dragonfruit", "kiwi",
	"lime", "mulberry", "nectar", "olive", "peach",
	"pear", "plum", "pomegranate", "quince", "rhubarb",
	"starfruit", "tomato", "ugli", "velvet", "wasabi",
	"xylophone", "yucca", "zinnia", "almond", "buttercup",
	"coconut", "dandelion", "eucalyptus", "fennel", "geranium",
	"honeysuckle", "iris", "jasmine", "lilac", "magnolia",
	"nutmeg", "oregano", "petunia", "rose", "sage",
	"thistle", "umbrella", "violet", "wisteria", "yarrow",
}

func main() {
	// 解析命令行参数
	var iterations int
	flag.IntVar(&iterations, "number", defaultIterations, "生成数量")
	flag.Parse()

	// 检查并创建CSV文件
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("无法打开文件: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 如果文件为空，写入标题行
	fileInfo, _ := file.Stat()
	if fileInfo.Size() == 0 {
		_, err = writer.WriteString("Email Address\n")
		if err != nil {
			log.Fatalf("写入文件失败: %v", err)
		}
		writer.Flush()
	}

	// 连接到服务器
	client, err := sshConnect(serverIP, username, password)
	if err != nil {
		log.Fatalf("SSH连接失败: %v", err)
	}
	defer client.Close()

	// 生成邮箱并执行Docker命令
	for i := 0; i < iterations; i++ {
		email := generateRandomEmail()

		// 构建要执行的Docker命令
		cmd := fmt.Sprintf(`docker exec -t mailserver setup email add "%s" "1qazXSW@pengy"`, email)
		err := runCommand(client, cmd)
		if err != nil {
			log.Printf("执行命令失败: %v", err)
			continue
		}

		// 将生成的邮箱记录到本地文件
		_, err = writer.WriteString(fmt.Sprintf("%s\n", email))
		if err != nil {
			log.Fatalf("写入文件失败: %v", err)
		}

		writer.Flush()

		// 可选：延迟一段时间以避免过快执行
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("所有邮箱地址已记录到 %s\n", outputFile)
}

// 生成随机邮箱
func generateRandomEmail() string {
	// 从单词库中选择两个单词
	word1 := wordList[randomIndex(len(wordList))]
	//word2 := wordList[randomIndex(len(wordList))]

	// 生成随机的数字部分
	bytes := make([]byte, 4)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatalf("生成随机数失败: %v", err)
	}
	randomNumber := hex.EncodeToString(bytes)

	return fmt.Sprintf("%s%s@yiyuanweb3.uk", word1, randomNumber)
}

// 生成随机索引
func randomIndex(max int) int {
	bytes := make([]byte, 1)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatalf("生成随机索引失败: %v", err)
	}
	return int(bytes[0]) % max
}

// 通过SSH连接到服务器
func sshConnect(server, user, password string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", server+":22", config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// 在远程服务器上执行命令
func runCommand(client *ssh.Client, cmd string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	// 捕获输出
	var outputBuf, errorBuf bytes.Buffer
	session.Stdout = &outputBuf
	session.Stderr = &errorBuf
	// 执行命令
	err = session.Run(cmd)
	if err != nil {
		log.Printf("命令执行失败: %v\n输出: %s\n错误: %s", err, outputBuf.String(), errorBuf.String())
		return err
	}

	fmt.Printf("命令输出: %s\n", outputBuf.String())
	return nil
}
