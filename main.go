package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/cloudflare-go"
)

// holds the values from the url request
type request struct {
	AppKey string `json:"key"`
	IPv4   string `json:"ipv4,omitempty"`
	IPv6   string `json:"ipv6,omitempty"`
}

// holds the response values
type reponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// holds the configuration values, read from envs
type config struct {
	appKey string
	apiKey string
	zone   string
	zoneID string
	record string
}

// holds current status
type status struct {
	LastUpdated time.Time `json:"last_updated"`
	IPv4        string    `json:"ipv4"`
	IPv6        string    `json:"ipv6"`
	Status      string    `json:"status"`
	mu          sync.RWMutex
}

// handle init before server start
func init() {

	log.Printf("Initializing server...")

	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize Cloudflare API client
	api, err := cloudflare.NewWithAPIToken(config.apiKey)
	if err != nil {
		log.Fatalf("Failed to initialize Cloudflare API client: %v", err)
	}

	// Look up Zone ID
	zoneID, err := getZoneID(api, config.zone)
	if err != nil {
		log.Fatalf("Failed to get Zone ID: %v", err)
	}

	// set correct zoneID
	config.zoneID = zoneID

	// Initialize status
	status := &status{}

	// Get current DNS records, only log IPv4 and IPv6 if available
	ipv4, ipv6, err := getCurrentDNSRecords(api, config.zoneID, config.record)
	if err != nil {
		log.Printf("Warning: Failed to get current DNS records: %v", err)
	} else {
		status.Update(ipv4, ipv6, "initialized")
		var ips []string
		if ipv4 != "" {
			ips = append(ips, fmt.Sprintf("IPv4: %s", ipv4))
		}
		if ipv6 != "" {
			ips = append(ips, fmt.Sprintf("IPv6: %s", ipv6))
		}
		log.Printf("Current DNS records - %s", strings.Join(ips, ", "))
	}

	log.Printf("Configured for %s", config.record)

	// Update handler registrations
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		statusHandler(w, status)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rootHandler(w, r, config, api, status)
	})
}

func main() {

	// Parse command line flags
	healthCheck := flag.Bool("health-check", false, "Run health check")
	flag.Parse()

	// run heathcheck
	if *healthCheck {
		runHealthCheck()
	}

	// setup server
	srv := &http.Server{
		Addr:    ":8080",
		Handler: http.DefaultServeMux,
	}

	// Start the server in a goroutine
	go func() {
		log.Printf("Server is ready to handle requests at :8080")
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Shutdown handling
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Printf("Server is shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Printf("Server shutdown completed")
}

// helth check against the server as native go instead of using curl
func runHealthCheck() {

	resp, err := http.Get("http://localhost:8080/status")
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Fatalf("Health check failed: %v", err)
	}
	os.Exit(0)
}

// Update status struct with new values
func (s *status) Update(ipv4, ipv6 string, status string) {

	// lock struct
	s.mu.Lock()
	defer s.mu.Unlock()

	// update time
	s.LastUpdated = time.Now()

	// update IPs
	if ipv4 != "" {
		s.IPv4 = ipv4
	}
	if ipv6 != "" {
		s.IPv6 = ipv6
	}

	// update status
	s.Status = status
}

// use provided Zone to get the Zone ID
func getZoneID(api *cloudflare.API, zoneName string) (string, error) {

	zones, err := api.ListZones(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to list zones: %w", err)
	}

	for _, zone := range zones {
		if zone.Name == zoneName {
			return zone.ID, nil
		}
	}
	return "", fmt.Errorf("zone %s not found", zoneName)
}

// load configuration from envs
func loadConfig() (*config, error) {

	config := &config{
		appKey: os.Getenv("APP_KEY"),
		apiKey: os.Getenv("CF_API_KEY"),
		zone:   os.Getenv("CF_ZONE"),
		record: os.Getenv("CF_RECORD"),
	}

	// Validate required fields
	var missingVars []string

	if config.appKey == "" {
		missingVars = append(missingVars, "APP_KEY")
	}
	if config.apiKey == "" {
		missingVars = append(missingVars, "CF_API_KEY")
	}
	if config.zone == "" {
		missingVars = append(missingVars, "CF_ZONE")
	}
	if config.record == "" {
		missingVars = append(missingVars, "CF_RECORD")
	}

	if len(missingVars) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missingVars, ", "))
	}

	return config, nil
}

// actual update of the DNS record
func updateDNSRecord(api *cloudflare.API, zoneID, recordName string, ipAddr string, recordType string) error {

	// List records with both name and type filters
	records, _, err := api.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Type: recordType,
		Name: recordName,
	})
	if err != nil {
		return fmt.Errorf("failed to list DNS records: %w", err)
	}

	log.Printf("Found %d existing %s records for %s", len(records), recordType, recordName)

	updateParams := cloudflare.UpdateDNSRecordParams{
		Type:    recordType,
		Name:    recordName,
		Content: ipAddr,
		TTL:     1, // Auto TTL
		Proxied: cloudflare.BoolPtr(false),
	}

	// create new record if none found, otherwise update first matching record
	if len(records) == 0 {
		_, err = api.CreateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.CreateDNSRecordParams{
			Type:    updateParams.Type,
			Name:    updateParams.Name,
			Content: updateParams.Content,
			TTL:     updateParams.TTL,
			Proxied: updateParams.Proxied,
		})
		if err != nil {
			return fmt.Errorf("failed to create DNS record: %w", err)
		}
		log.Printf("Created new %s record for %s: %s", recordType, recordName, ipAddr)
	} else {
		// Update first matching record
		updateParams.ID = records[0].ID
		_, err = api.UpdateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), updateParams)
		if err != nil {
			return fmt.Errorf("failed to update DNS record: %w", err)
		}
		log.Printf("Updated existing %s record for %s: %s", recordType, recordName, ipAddr)
	}

	return nil
}

func statusHandler(w http.ResponseWriter, status *status) {

	status.mu.RLock()
	defer status.mu.RUnlock()
	sendJSONResponse(w, status, http.StatusOK)
}

func rootHandler(w http.ResponseWriter, r *http.Request, config *config, api *cloudflare.API, status *status) {

	if r.URL.Path != "/" {
		log.Printf("Invalid path requested: %s", r.URL.Path)
		http.NotFound(w, r)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	request := request{
		AppKey: query.Get("key"),
		IPv4:   query.Get("ipv4"),
		IPv6:   query.Get("ipv6"),
	}

	// Log request details
	var ips []string
	if request.IPv4 != "" {
		ips = append(ips, fmt.Sprintf("IPv4: %s", request.IPv4))
	}
	if request.IPv6 != "" {
		ips = append(ips, fmt.Sprintf("IPv6: %s", request.IPv6))
	}
	log.Printf("Processing request from %s - %s", r.RemoteAddr, strings.Join(ips, ", "))

	// First, validate the app key (no logging of key values)
	if request.AppKey != config.appKey {
		log.Printf("Error: Invalid application key from %s", r.RemoteAddr)
		sendJSONResponse(w, reponse{Status: "error", Message: "Invalid application key"}, http.StatusUnauthorized)
		return
	}

	// Then validate IP addresses
	if request.IPv4 == "" && request.IPv6 == "" {
		log.Printf("Error: No IP addresses provided")
		sendJSONResponse(w, reponse{Status: "error", Message: "At least one IP address (IPv4 or IPv6) is required"}, http.StatusBadRequest)
		return
	}

	// Validate IPv4 if provided
	if request.IPv4 != "" {
		if ip := net.ParseIP(request.IPv4); ip == nil || ip.To4() == nil {
			log.Printf("Error: Invalid IPv4 address provided: %s", request.IPv4)
			sendJSONResponse(w, reponse{Status: "error", Message: "Invalid IPv4 address"}, http.StatusBadRequest)
			return
		}
	}

	// Validate IPv6 if provided
	if request.IPv6 != "" {
		if ip := net.ParseIP(request.IPv6); ip == nil || ip.To4() != nil {
			log.Printf("Error: Invalid IPv6 address provided: %s", request.IPv6)
			sendJSONResponse(w, reponse{Status: "error", Message: "Invalid IPv6 address"}, http.StatusBadRequest)
			return
		}
	}

	// All validation passed, update DNS records, track any errors
	var updateErrors []string

	// Process updates
	if request.IPv4 != "" {
		if err := updateDNSRecord(api, config.zoneID, config.record, request.IPv4, "A"); err != nil {
			updateErrors = append(updateErrors, fmt.Sprintf("IPv4: %v", err))
		}
	}

	if request.IPv6 != "" {
		if err := updateDNSRecord(api, config.zoneID, config.record, request.IPv6, "AAAA"); err != nil {
			updateErrors = append(updateErrors, fmt.Sprintf("IPv6: %v", err))
		}
	}

	// check if errors occured and update status
	if len(updateErrors) > 0 {
		errMsg := fmt.Sprintf("Failed to update DNS records: %s", strings.Join(updateErrors, "; "))
		log.Printf("Error: %s", errMsg)
		status.Update(request.IPv4, request.IPv6, "error")
		sendJSONResponse(w, reponse{Status: "error", Message: errMsg}, http.StatusInternalServerError)
		return
	}

	// Update status with success
	status.Update(request.IPv4, request.IPv6, "success") // Uses current time for successful updates
	sendJSONResponse(w, reponse{
		Status:  "success",
		Message: fmt.Sprintf("Updated DNS records - IPv4: %s, IPv6: %s", request.IPv4, request.IPv6),
	}, http.StatusOK)
}

// send JSON response
func sendJSONResponse(w http.ResponseWriter, response interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// get current DNS records for initial status, before any updates ran
func getCurrentDNSRecords(api *cloudflare.API, zoneID, recordName string) (string, string, error) {
	records, _, err := api.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Name: recordName,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to list DNS records: %w", err)
	}

	var ipv4, ipv6 string
	for _, record := range records {
		if record.Type == "A" {
			ipv4 = record.Content
		} else if record.Type == "AAAA" {
			ipv6 = record.Content
		}
	}

	return ipv4, ipv6, nil
}
