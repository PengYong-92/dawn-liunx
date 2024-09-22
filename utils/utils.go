package utils

import (
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
