package utils

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
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
