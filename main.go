package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct{
	fileServerHits atomic.Int32
}

type chirp struct {
	Body string `json:"body"`
}

func main() {
	cfg := apiConfig{}
	mux := http.NewServeMux()

	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("GET /admin/metrics", cfg.getMetricsHandler)
	mux.HandleFunc("POST /admin/reset", cfg.resetMetricsHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirp)

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
	w.Header().Set("Content-Type", "text/html")
	html := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", count)
	w.Write([]byte(html))
}

//reset handler: resets the counter 
func (cfg *apiConfig) resetMetricsHandler(w http.ResponseWriter, req *http.Request) {
	cfg.fileServerHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("Metrics reset to 0"))
}


//validate handler: validates the chirps 
func validateChirp(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	reqChirp := chirp{}
	err := decoder.Decode(&reqChirp)

	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
	} else if len(reqChirp.Body) > 140 {
		w.WriteHeader(400)
		w.Write([]byte("{\"error\": \"Chirp is too long\"}"))
	} else if hasProfanity(reqChirp.Body){
		cleaned_chirp := cleanProfanity(reqChirp.Body)
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf("{\"cleaned_body\": \"%s\"}", cleaned_chirp)))
	} else {
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf("{\"cleaned_body\": \"%s\"}", reqChirp.Body)))
	}
}

func hasProfanity(text string) bool {
	words := strings.Fields(text)
	for _, word := range words {
		if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
			return true
		}
	}
	return false
}

func cleanProfanity(text string) string {
	cleaned_chirp := ""
	words := strings.Fields(text)
	for _, word := range words {
		if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
			cleaned_chirp += "**** "
		} else {
			cleaned_chirp += word + " "
		}
	}
	return cleaned_chirp[:len(cleaned_chirp)-1]
}