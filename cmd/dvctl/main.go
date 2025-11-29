package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	switch cmd {
	case "health":
		doHealth(args)
	case "info":
		doInfo(args)
	case "list":
		doList(args)
	case "logs":
		doLogs(args)
	case "start", "stop", "restart":
		doControl(cmd, args)
	default:
		usage()
	}
}

func baseURLFlag(fs *flag.FlagSet) *string {
	return fs.String("url", "http://127.0.0.1:8364", "base URL of dockervision agent")
}

func tokenHeader(req *http.Request) {
	if tok := os.Getenv("DV_AUTH_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}

func doHealth(args []string) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	u := baseURLFlag(fs)
	_ = fs.Parse(args)
	resp, err := get(*u + "/health")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(resp)
}

func doInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	u := baseURLFlag(fs)
	_ = fs.Parse(args)
	resp, err := get(*u + "/system/info")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(resp)
}

func doList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	u := baseURLFlag(fs)
	_ = fs.Parse(args)
	resp, err := get(*u + "/containers")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(resp)
}

func doLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	u := baseURLFlag(fs)
	id := fs.String("id", "", "container id")
	lines := fs.Int("n", 100, "lines tail")
	_ = fs.Parse(args)
	if *id == "" {
		fmt.Println("id required")
		return
	}
	url := fmt.Sprintf("%s/containers/%s/logs?lines=%d&stdout=true&stderr=true", *u, *id, *lines)
	body, err := rawGet(url)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Print(body)
}

func doControl(action string, args []string) {
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	u := baseURLFlag(fs)
	id := fs.String("id", "", "container id")
	_ = fs.Parse(args)
	if *id == "" {
		fmt.Println("id required")
		return
	}
	url := fmt.Sprintf("%s/containers/%s/%s", *u, *id, action)
	resp, err := post(url)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(resp)
}

func get(url string) (string, error) {
	return doRequest(http.MethodGet, url)
}

func rawGet(url string) (string, error) {
	return doRequest(http.MethodGet, url)
}

func post(url string) (string, error) {
	return doRequest(http.MethodPost, url)
}

func doRequest(method, url string) (string, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", err
	}
	tokenHeader(req)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}
	var pretty map[string]any
	if json.Unmarshal(b, &pretty) == nil {
		out, _ := json.MarshalIndent(pretty, "", "  ")
		return string(out), nil
	}
	return string(b), nil
}

func usage() {
	fmt.Println("dvctl commands:")
	fmt.Println("  health                   - check agent health")
	fmt.Println("  info                     - engine info")
	fmt.Println("  list                     - list containers")
	fmt.Println("  logs -id <cid> [-n N]    - tail logs")
	fmt.Println("  start|stop|restart -id <cid>  - control container")
	fmt.Println("Env: DV_AUTH_TOKEN optional bearer")
}
