package main

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
)

type apiConfig struct{
	fileServerHits atomic.Int32
}

func main() {
	cfg := apiConfig{}
	mux := http.NewServeMux()

	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("GET /api/metrics", cfg.getMetricsHandler)
	mux.HandleFunc("POST /api/reset", cfg.resetMetricsHandler)

	server := http.Server{
		Addr: ":8080",
		Handler: mux,
	}

	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("Server error: ", err)
	}
}

// health handler: checks if server is running or not 
func healthzHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

// metrics middleware: increments counter on each request
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

//metrics handler: returns the current counter
func (cfg *apiConfig) getMetricsHandler(w http.ResponseWriter, req *http.Request) {
	count := cfg.fileServerHits.Load()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("Hits: " + strconv.Itoa(int(count))))
}

//reset handler: resets the counter 
func (cfg *apiConfig) resetMetricsHandler(w http.ResponseWriter, req *http.Request) {
	cfg.fileServerHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("Metrics reset to 0"))
}