package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/openadp/openadp/pkg/client"
)

const version = "1.0.0"

func main() {
	var (
		serverURL   = flag.String("server", "", "OpenADP server URL (required)")
		format      = flag.String("format", "pretty", "Output format: pretty, json, raw")
		help        = flag.Bool("help", false, "Show help information")
		showVersion = flag.Bool("version", false, "Show version information")
		verbose     = flag.Bool("verbose", false, "Show detailed information")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("OpenADP Server Info Tool v%s\n", version)
		return
	}

	if *help {
		showHelp()
		return
	}

	if *serverURL == "" {
		fmt.Println("Error: -server is required")
		showHelp()
		os.Exit(1)
	}

	// Ensure URL has proper protocol
	if !strings.HasPrefix(*serverURL, "http://") && !strings.HasPrefix(*serverURL, "https://") {
		*serverURL = "https://" + *serverURL
	}

	if *verbose {
		fmt.Printf("🔍 Connecting to server: %s\n", *serverURL)
	}

	// Create client and get server info
	openadpClient := client.NewOpenADPClient(*serverURL)
	serverInfo, err := openadpClient.GetServerInfo()
	if err != nil {
		fmt.Printf("❌ Error getting server info: %v\n", err)
		os.Exit(1)
	}

	// Display results based on format
	switch *format {
	case "json":
		printJSON(serverInfo)
	case "raw":
		printRaw(serverInfo)
	case "pretty":
		fallthrough
	default:
		printPretty(serverInfo, *verbose)
	}
}

func showHelp() {
	fmt.Printf(`OpenADP Server Info Tool v%s

Usage: %s [options]

Options:
  -server string
        OpenADP server URL (required)
        Examples: 
          -server https://server1.openadp.org
          -server localhost:8080
          -server server.example.com

  -format string
        Output format: pretty, json, raw (default "pretty")
        pretty: Human-readable formatted output
        json:   Pretty-printed JSON
        raw:    Raw JSON response

  -verbose
        Show detailed information and connection status

  -version
        Show version information

  -help
        Show this help message

Examples:
  # Get server info with pretty formatting
  %s -server https://server1.openadp.org

  # Get raw JSON response
  %s -server https://server1.openadp.org -format json

  # Verbose output with connection details
  %s -server localhost:8080 -verbose

`, version, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func printPretty(serverInfo map[string]interface{}, verbose bool) {
	fmt.Println("📋 OpenADP Server Information")
	fmt.Println("=" + strings.Repeat("=", 40))

	// Version
	if version, ok := serverInfo["version"].(string); ok && version != "" {
		fmt.Printf("🏷️  Version: %s\n", version)
	}

	// Noise-NK Public Key
	if noiseKey, ok := serverInfo["noise_nk_public_key"].(string); ok && noiseKey != "" {
		fmt.Printf("🔐 Noise-NK Public Key: %s\n", noiseKey)
		if verbose {
			fmt.Printf("   (Supports encrypted communication)\n")
		}
	} else {
		fmt.Printf("🔓 Noise-NK Public Key: Not available\n")
		if verbose {
			fmt.Printf("   (Server does not support encrypted communication)\n")
		}
	}

	// Capabilities
	if capabilities, ok := serverInfo["capabilities"].([]interface{}); ok && len(capabilities) > 0 {
		fmt.Printf("⚡ Capabilities:\n")
		for i, cap := range capabilities {
			if capStr, ok := cap.(string); ok {
				fmt.Printf("   %d. %s\n", i+1, capStr)
			}
		}
	}

	// Monitoring information
	if monitoring, ok := serverInfo["monitoring"].(map[string]interface{}); ok {
		fmt.Printf("📊 Monitoring:\n")

		if queries, ok := monitoring["queries_current_hour"].(float64); ok {
			fmt.Printf("   Current hour queries: %.0f\n", queries)
		}

		if queries24h, ok := monitoring["queries_last_24h"].(float64); ok {
			fmt.Printf("   Last 24h queries: %.0f\n", queries24h)
		}

		if uptime, ok := monitoring["uptime_start"].(string); ok && uptime != "" {
			fmt.Printf("   Uptime since: %s\n", uptime)
		}

		if responseTime, ok := monitoring["response_time_avg_ms"].(float64); ok {
			fmt.Printf("   Avg response time: %.2f ms\n", responseTime)
		}

		if errorRate, ok := monitoring["error_rate_percent"].(float64); ok {
			fmt.Printf("   Error rate: %.2f%%\n", errorRate)
		}

		if verbose {
			if histogram, ok := monitoring["last_hour_histogram"].([]interface{}); ok && len(histogram) > 0 {
				fmt.Printf("   Last hour histogram: %v\n", histogram)
			}
		}
	}

	fmt.Println("=" + strings.Repeat("=", 40))
	fmt.Println("✅ Successfully retrieved server information")
}

func printJSON(serverInfo map[string]interface{}) {
	jsonBytes, err := json.MarshalIndent(serverInfo, "", "  ")
	if err != nil {
		fmt.Printf("❌ Error formatting JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonBytes))
}

func printRaw(serverInfo map[string]interface{}) {
	jsonBytes, err := json.Marshal(serverInfo)
	if err != nil {
		fmt.Printf("❌ Error formatting JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonBytes))
}
