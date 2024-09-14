package main

import (
	"fmt"
	capsolver_go "github.com/capsolver/capsolver-go"
	"log"
	"os"
)

func main() {
	os.Setenv("http_proxy", "http://172.16.100.237:7899")
	os.Setenv("https_proxy", "http://172.16.100.237:7899")

	apikey := "CAP-C7314376D9418C07CF7CB36FEBF1C62B"
	capSolver := capsolver_go.CapSolver{ApiKey: apikey}
	solution, err := capSolver.Solve(map[string]any{
		"type":       "HCaptchaTaskProxyLess",
		"websiteURL": "https://faucet.0g.ai/",
		//"websiteURL": "faucet.0g.ai",
		"websiteKey": "06ee6b5b-ef03-4491-b8ea-01fb5a80256f",
	})
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Println(solution)
}
