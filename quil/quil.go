package main

import (
	"fmt"
	"strings"
)

func main() {
	//ips := []string{"172.16.111.5", "172.16.100.40", "172.16.100.15"} // IP 地址
	//ips := []string{"172.16.100.13", "172.16.100.20", "172.16.100.26", "172.16.100.18", "172.16.100.24", "172.16.100.8", "172.16.100.249"}
	ips := []string{"172.16.100.34", "172.16.100.8", "172.16.100.13"} // IP 地址
	maxCores := 255                                                   // 最大核心数

	// 定义存储结果的变量
	var addrs []string

	// 遍历 IP 地址
	for c, ip := range ips {
		// 为每个 IP 地址生成端口地址
		for count := 0; count < maxCores; count++ {
			if c == 0 && count == maxCores-1 {
				break // 如果是第一个 IP，跳过最后一个端口
			}
			addr := fmt.Sprintf("/ip4/%s/tcp/%d", ip, 40000+(count+1))
			addrs = append(addrs, addr)
		}
	}

	// 使用 strings.Join 拼接结果
	fmt.Printf("\ndataWorkerMultiaddrs: [\n%s\n]\n\n", strings.Join(addrs, ",\n"))
}
