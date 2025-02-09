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

type UpdateRequest struct {
	APPKey string `json:"key"`
	IPv4   string `json:"ipv4,omitempty"`
	IPv6   string `json:"ipv6,omitempty"`
}

type UpdateResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type Config struct {
	APPKey     string
	APIKey     string
	ZoneID     string
	RecordName string
}

type UpdateStatus struct {
	LastUpdated time.Time `json:"last_updated"`
	IPv4        string    `json:"ipv4"`
	IPv6        string    `json:"ipv6"`
	Status      string    `json:"status"`
	mu          sync.RWMutex
}

func NewUpdateStatus() *UpdateStatus {
	return &UpdateStatus{
		Status: "not_run",
	}
}

func (s *UpdateStatus) Update(ipv4, ipv6 string, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastUpdated = time.Now()
	if ipv4 != "" {
		s.IPv4 = ipv4
	}
	if ipv6 != "" {
		s.IPv6 = ipv6
	}
	s.Status = status
}

func loadConfig() (*Config, error) {
	config := &Config{
		APPKey:     os.Getenv("APP_KEY"),
		APIKey:     os.Getenv("CF_API_KEY"),
		ZoneID:     os.Getenv("CF_ZONE"),
		RecordName: os.Getenv("CF_RECORD"),
	}

	// Validate required fields
	var missingVars []string

	if config.APPKey == "" {
		missingVars = append(missingVars, "APP_KEY")
	}
	if config.APIKey == "" {
		missingVars = append(missingVars, "CF_API_KEY")
	}
	if config.ZoneID == "" {
		missingVars = append(missingVars, "CF_ZONE")
	}
	if config.RecordName == "" {
		missingVars = append(missingVars, "CF_RECORD")
	}

	if len(missingVars) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missingVars, ", "))
	}

	return config, nil
}

func updateDNSRecord(api *cloudflare.API, zoneID, recordName string, ipAddr string, recordType string) error {
	records, _, err := api.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Name: recordName,
		Type: recordType,
	})
	if err != nil {
		return fmt.Errorf("failed to list DNS records: %w", err)
	}

	record := cloudflare.DNSRecord{
		Name:    recordName,
		Type:    recordType,
		Content: ipAddr,
		TTL:     1, // Auto TTL
		Proxied: cloudflare.BoolPtr(false),
	}

	if len(records) == 0 {
		// Create new record
		_, err = api.CreateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.CreateDNSRecordParams{
			Type:    record.Type,
			Name:    record.Name,
			Content: record.Content,
			TTL:     record.TTL,
			Proxied: record.Proxied,
		})
		if err != nil {
			return fmt.Errorf("failed to create DNS record: %w", err)
		}
		log.Printf("Created new %s record for %s: %s", recordType, recordName, ipAddr)
	} else {
		// Update existing record
		record.ID = records[0].ID
		_, err = api.UpdateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.UpdateDNSRecordParams{
			ID:      record.ID,
			Type:    record.Type,
			Name:    record.Name,
			Content: record.Content,
			TTL:     record.TTL,
			Proxied: record.Proxied,
		})
		if err != nil {
			return fmt.Errorf("failed to update DNS record: %w", err)
		}
		log.Printf("Updated %s record for %s: %s", recordType, recordName, ipAddr)
	}

	return nil
}

func statusHandler(w http.ResponseWriter, status *UpdateStatus) {
	status.mu.RLock()
	defer status.mu.RUnlock()

	sendJSONResponse(w, status, http.StatusOK)
}

func rootHandler(w http.ResponseWriter, r *http.Request, config *Config, api *cloudflare.API, status *UpdateStatus) {
	log.Printf("Incoming request from %s: %s%s", r.RemoteAddr, r.Host, r.URL.String())

	if r.URL.Path != "/" {
		log.Printf("Invalid path requested: %s", r.URL.Path)
		http.NotFound(w, r)
		return
	}

	query := r.URL.Query()
	request := UpdateRequest{
		APPKey: query.Get("key"),
		IPv4:   query.Get("ipv4"),
		IPv6:   query.Get("ipv6"),
	}

	log.Printf("Processing request from %s - IPv4: %s, IPv6: %s",
		r.RemoteAddr, request.IPv4, request.IPv6)

	// First, validate the app key
	if request.APPKey != config.APPKey {
		log.Printf("Error: Invalid application key provided")
		sendJSONResponse(w, UpdateResponse{Status: "error", Message: "Invalid application key"}, http.StatusUnauthorized)
		return
	}

	// Then validate IP addresses
	if request.IPv4 == "" && request.IPv6 == "" {
		log.Printf("Error: No IP addresses provided")
		sendJSONResponse(w, UpdateResponse{Status: "error", Message: "At least one IP address (IPv4 or IPv6) is required"}, http.StatusBadRequest)
		return
	}

	// Validate IPv4 if provided
	if request.IPv4 != "" {
		if ip := net.ParseIP(request.IPv4); ip == nil || ip.To4() == nil {
			log.Printf("Error: Invalid IPv4 address provided: %s", request.IPv4)
			sendJSONResponse(w, UpdateResponse{Status: "error", Message: "Invalid IPv4 address"}, http.StatusBadRequest)
			return
		}
	}

	// Validate IPv6 if provided
	if request.IPv6 != "" {
		if ip := net.ParseIP(request.IPv6); ip == nil || ip.To4() != nil {
			log.Printf("Error: Invalid IPv6 address provided: %s", request.IPv6)
			sendJSONResponse(w, UpdateResponse{Status: "error", Message: "Invalid IPv6 address"}, http.StatusBadRequest)
			return
		}
	}

	// All validation passed, update DNS records
	var updateErrors []string

	// Process updates
	if request.IPv4 != "" {
		if err := updateDNSRecord(api, config.ZoneID, config.RecordName, request.IPv4, "A"); err != nil {
			updateErrors = append(updateErrors, fmt.Sprintf("IPv4: %v", err))
		}
	}

	if request.IPv6 != "" {
		if err := updateDNSRecord(api, config.ZoneID, config.RecordName, request.IPv6, "AAAA"); err != nil {
			updateErrors = append(updateErrors, fmt.Sprintf("IPv6: %v", err))
		}
	}

	if len(updateErrors) > 0 {
		errMsg := fmt.Sprintf("Failed to update DNS records: %s", strings.Join(updateErrors, "; "))
		log.Printf("Error: %s", errMsg)
		status.Update(request.IPv4, request.IPv6, "error")
		sendJSONResponse(w, UpdateResponse{Status: "error", Message: errMsg}, http.StatusInternalServerError)
		return
	}

	status.Update(request.IPv4, request.IPv6, "success")
	sendJSONResponse(w, UpdateResponse{
		Status:  "success",
		Message: fmt.Sprintf("Updated DNS records - IPv4: %s, IPv6: %s", request.IPv4, request.IPv6),
	}, http.StatusOK)
}

func sendJSONResponse(w http.ResponseWriter, response interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func main() {
	healthCheck := flag.Bool("health-check", false, "Run health check")
	flag.Parse()

	if *healthCheck {
		resp, err := http.Get("http://localhost:8080/status")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("Initializing server...")

	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize Cloudflare API client
	api, err := cloudflare.NewWithAPIToken(config.APIKey)
	if err != nil {
		log.Fatalf("Failed to initialize Cloudflare API client: %v", err)
	}

	updateStatus := NewUpdateStatus()

	srv := &http.Server{
		Addr:    ":8080",
		Handler: http.DefaultServeMux,
	}

	log.Printf("Configured for zone %s and record %s", config.ZoneID, config.RecordName)

	// Update handler registrations to include status
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		statusHandler(w, updateStatus)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rootHandler(w, r, config, api, updateStatus)
	})

	// Channel to listen for errors coming from the listener.
	serverErrors := make(chan error, 1)

	// Start the server
	go func() {
		log.Printf("Server is ready to handle requests at :8080")
		serverErrors <- srv.ListenAndServe()
	}()

	// Channel to listen for an interrupt or terminate signal from the OS.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Blocking select waiting for either a server error or a signal.
	select {
	case err := <-serverErrors:
		log.Printf("Server error: %v", err)
		log.Fatalf("Server terminated unexpectedly")

	case sig := <-shutdown:
		log.Printf("Beginning shutdown sequence. Caught signal: %v", sig)

		// Give outstanding requests a deadline for completion.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Asking listener to shut down and shed load.
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("WARNING: Graceful shutdown failed: %v", err)
			if err := srv.Close(); err != nil {
				log.Printf("ERROR: Failed to close server: %v", err)
			}
		} else {
			log.Printf("Server shutdown completed successfully")
		}
	}
}
