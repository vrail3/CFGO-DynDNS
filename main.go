package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type UpdateRequest struct {
	APIKey string `json:"key"`
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

func rootHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Incoming request from %s: %s%s", r.RemoteAddr, r.Host, r.URL.String())

	if r.URL.Path != "/" {
		log.Printf("Invalid path requested: %s", r.URL.Path)
		http.NotFound(w, r)
		return
	}

	query := r.URL.Query()
	request := UpdateRequest{
		APIKey: query.Get("key"),
		IPv4:   query.Get("ipv4"),
		IPv6:   query.Get("ipv6"),
	}

	log.Printf("Processing request from %s - IPv4: %s, IPv6: %s",
		r.RemoteAddr, request.IPv4, request.IPv6)

	// Validate request
	if request.APIKey == "" {
		log.Printf("Error: Missing API key in request")
		sendJSONResponse(w, UpdateResponse{Status: "error", Message: "API key is required"}, http.StatusBadRequest)
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

	addresses := []string{}
	if request.IPv4 != "" {
		addresses = append(addresses, "IPv4: "+request.IPv4)
	}
	if request.IPv6 != "" {
		addresses = append(addresses, "IPv6: "+request.IPv6)
	}
	log.Printf("Successfully validated update request with %s", strings.Join(addresses, ", "))

	// If we get here, everything is valid
	sendJSONResponse(w, UpdateResponse{
		Status:  "success",
		Message: fmt.Sprintf("Received - IPv4: %s, IPv6: %s", request.IPv4, request.IPv6),
	}, http.StatusOK)
}

func sendJSONResponse(w http.ResponseWriter, response interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("Initializing server...")

	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	srv := &http.Server{
		Addr:    ":8080",
		Handler: http.DefaultServeMux,
	}

	log.Printf("Configured for zone %s and record %s", config.ZoneID, config.RecordName)

	http.HandleFunc("/", rootHandler)

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
