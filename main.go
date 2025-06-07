package main

import (
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct{
	fileServerHits atomic.Int32
	db *database.Queries
	platform string
}

type chirp struct {
	ID		  uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
}

type user struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL must be set")
	}

	dbConn, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error opening database: %s", err)
	}

	pltfrm := os.Getenv("PLATFORM")
	dbQueries := database.New(dbConn)
	cfg := apiConfig{
		fileServerHits: atomic.Int32{},
		db: dbQueries,
		platform: pltfrm,
	}

	mux := http.NewServeMux()
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("GET /admin/metrics", cfg.getMetricsHandler)
	mux.HandleFunc("POST /admin/reset", cfg.resetMetricsHandler)
	mux.HandleFunc("POST /api/users", cfg.createUsers)
	mux.HandleFunc("POST /api/chirps", cfg.createChirps)
	mux.HandleFunc("GET /api/chirps", cfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.getChirp)

	server := http.Server{
		Addr: ":8080",
		Handler: mux,
	}

	err = server.ListenAndServe()
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
	if cfg.platform != "dev" {
		w.WriteHeader(403)
		w.Write([]byte("Cannot reset metrics and users from a non-dev platform"))
	}

	cfg.fileServerHits.Store(0)
	cfg.db.DeleteUsers(req.Context())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("Metrics reset to 0 & all users deleted"))
}

// user create handler: creates a user in the db 
func (cfg *apiConfig) createUsers(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	usr := user{}
	err := decoder.Decode(&usr)

	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
	} else {
		userDb, _ := cfg.db.CreateUser(req.Context(), usr.Email)
		userRes := user(userDb)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		res, _ := json.Marshal(userRes)
		w.Write(res)
	}
}

// chirp create handler: creates a chirp in the db 
func (cfg *apiConfig) createChirps(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	chrp := chirp{}
	err := decoder.Decode(&chrp)

	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
	} else if len(chrp.Body) > 140 {
		w.WriteHeader(400)
		w.Write([]byte("{\"error\": \"Chirp is too long\"}"))
	} else {
		chrp.Body = cleanProfanity(chrp.Body)

		chirpParams := database.CreateChirpParams{
			Body: chrp.Body,
			UserID: chrp.UserId,
		}

		chirpDb, err := cfg.db.CreateChirp(req.Context(), chirpParams)
		if err != nil {
			log.Printf("CreateChirp error: %v", err)
			http.Error(w, `{"error": "Could not create chirp"}`, http.StatusInternalServerError)
			return
		}
	
		chirpRes := chirp{
			ID:        chirpDb.ID,
			CreatedAt: chirpDb.CreatedAt,
			UpdatedAt: chirpDb.UpdatedAt,
			Body:      chirpDb.Body,
			UserId:    chirpDb.UserID, 
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		res, _ := json.Marshal(chirpRes)
		w.Write(res)
	}	
}

//helper function for createChirps handler
func cleanProfanity(text string) string {
	if !hasProfanity(text) {
		return text
	}

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

//helper function for createChirps handler
func hasProfanity(text string) bool {
	words := strings.Fields(text)
	for _, word := range words {
		if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
			return true
		}
	}
	return false
}

// chirp get handler: gets all chirps in the db 
func (cfg *apiConfig) getAllChirps(w http.ResponseWriter, req *http.Request) {
	chrpsDb, _ := cfg.db.GetAllChirps(req.Context())
	var chrpsRes []chirp
	for _, chrpDb := range chrpsDb {
		chrpRes := chirp{
			ID:        chrpDb.ID,
			CreatedAt: chrpDb.CreatedAt,
			UpdatedAt: chrpDb.UpdatedAt,
			Body:      chrpDb.Body,
			UserId:    chrpDb.UserID,
		}
		chrpsRes = append(chrpsRes, chrpRes)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	res, _ := json.Marshal(chrpsRes)
	w.Write(res)
}

//chirp get handler: gets the chirp for the given chirp id 
func (cfg *apiConfig) getChirp(w http.ResponseWriter, req *http.Request) {
	chrpID, _ := uuid.Parse(req.PathValue("chirpID"))
	chrpDb, err := cfg.db.GetChirp(req.Context(), chrpID)
	if err != nil {
		w.WriteHeader(404)
		w.Write([]byte("Could not find the chirp"))
	} else {
		chrpRes := chirp{
			ID:        chrpDb.ID,
			CreatedAt: chrpDb.CreatedAt,
			UpdatedAt: chrpDb.UpdatedAt,
			Body:      chrpDb.Body,
			UserId:    chrpDb.UserID,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		res, _ := json.Marshal(chrpRes)
		w.Write(res)
	}
}
