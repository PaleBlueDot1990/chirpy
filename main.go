package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
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
	secret string
	polka_key string
}

type chirp struct {
	ID		  uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
}

type user struct {
	ID              uuid.UUID     `json:"id"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
	Email           string        `json:"email"`
	Password        string        `json:"password"`
	HashedPassword  string        `json:"hashed_password"`
}

type userResponse struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type RefreshedAccessToken struct {
	Token string `json:"token"`
}

type UserUpgradedEvent struct {
	Event string         `json:"event"`
	Data  UserUpgradeData `json:"data"`
}

type UserUpgradeData struct {
	UserID string `json:"user_id"`
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

	scrt := os.Getenv("SECRET")
	pltfrm := os.Getenv("PLATFORM")
	dbQueries := database.New(dbConn)
	pkey := os.Getenv("POLKA_KEY")
	cfg := apiConfig{
		fileServerHits: atomic.Int32{},
		db: dbQueries,
		platform: pltfrm,
		secret: scrt,
		polka_key: pkey,
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
	mux.HandleFunc("POST /api/login", cfg.login)
	mux.HandleFunc("POST /api/refresh", cfg.refreshToken)
	mux.HandleFunc("POST /api/revoke", cfg.revokeToken)
	mux.HandleFunc("PUT /api/users", cfg.updateUsers)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.DeleteChirps)
	mux.HandleFunc("POST /api/polka/webhooks", cfg.UpgradeUsersToChirpyRed)

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
		hashed_password, _ := auth.HashPassword(usr.Password)

		dbParams := database.CreateUserParams{
			Email:          usr.Email,
			HashedPassword: hashed_password,
		}

		userDb, _ := cfg.db.CreateUser(req.Context(), dbParams)

		userRes := userResponse{
			ID:          userDb.ID,
			CreatedAt:   userDb.CreatedAt,
			UpdatedAt:   userDb.UpdatedAt,
			Email:       userDb.Email,
			IsChirpyRed: userDb.IsChirpyRed,
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		res, _ := json.Marshal(userRes)
		w.Write(res)
	}
}

// user login handler: login the user
func (cfg *apiConfig) login(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	usr := user{}
	err := decoder.Decode(&usr)

	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
	} else {
		userDb, err := cfg.db.GetUserByEmail(req.Context(), usr.Email)
		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Incorrect email"))
			return
		}
		
		hashed_password := userDb.HashedPassword
		err = auth.CheckPasswordHash(hashed_password, usr.Password)
		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Incorrect password"))
			return 
		}

		refresh_token, _ := auth.MakeRefreshTokens()
		dbParams := database.CreateRefreshTokensParams{
			Token: refresh_token,
			UserID: userDb.ID,
		}
		cfg.db.CreateRefreshTokens(req.Context(), dbParams)

		token, _ := auth.MakeJWT(userDb.ID, cfg.secret, time.Second * 3600)
		userRes := userResponse{
			ID:           userDb.ID,
			CreatedAt:    userDb.CreatedAt,
			UpdatedAt:    userDb.UpdatedAt,
			Email:        userDb.Email,
			Token:        token,
			RefreshToken: refresh_token,
			IsChirpyRed:  userDb.IsChirpyRed,
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
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
		return 
	} 
	
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("No bearer token is present"))
		return 
	} 
	
	user_id, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Bad credentials"))
		return
	}

	if len(chrp.Body) > 140 {
		w.WriteHeader(400)
		w.Write([]byte("{\"error\": \"Chirp is too long\"}"))
		return
	} 

	chrp.Body = cleanProfanity(chrp.Body)

	chirpParams := database.CreateChirpParams{
		Body: chrp.Body,
		UserID: user_id,
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
	author_id := req.URL.Query().Get("author_id")
	var user_id uuid.UUID
	var err error = nil 
	if author_id != "" {
		user_id, err = uuid.Parse(author_id)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong"))
			return 
		}
	}
	
	var chrpsDb []database.Chirp
	if author_id == "" {
		chrpsDb, _ = cfg.db.GetAllChirps(req.Context());
	} else {
		chrpsDb, _ = cfg.db.GetChirpsOfAuthor(req.Context(), user_id)
	}

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

	order := req.URL.Query().Get("sort")
	if order == "desc" {
		slices.Reverse(chrpsRes)
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

//refresh token handler: refreshes the jwt access token 
func (cfg *apiConfig) refreshToken(w http.ResponseWriter, req *http.Request) {
	refresh_token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("No refresh token available"))
		return
	}

	dbResponse, err := cfg.db.GetUserFromRefreshToken(req.Context(), refresh_token)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Invalid refresh token"))
		return
	}

	if dbResponse.ExpiresAt.Before(time.Now()) {
		w.WriteHeader(401)
		w.Write([]byte("Refresh token has expires"))
		return
	}

	if dbResponse.ExpiresAt.Before(time.Now()) {
		w.WriteHeader(401)
		w.Write([]byte("Refresh token has expires"))
		return
	}

	if !dbResponse.RevokedAt.Time.IsZero() {
		w.WriteHeader(401)
		w.Write([]byte("Refresh token has been revoked"))
		return
	}

	token, err := auth.MakeJWT(dbResponse.UserID, cfg.secret, time.Second * 3600)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Error creating access token"))
		return
	}

	tkn := RefreshedAccessToken{
		Token: token,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	res, _ := json.Marshal(tkn)
	w.Write(res)
}

//revoke token handler: revokes the refresh token 
func (cfg *apiConfig) revokeToken(w http.ResponseWriter, req *http.Request) {
	refresh_token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("No refresh token available"))
		return
	}

	err = cfg.db.UpdateRefreshTokenRevokeStatus(req.Context(), refresh_token)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Error updating revoke status of refresh token"))
		return
	}

	w.WriteHeader(204)
}

//update users handler: updates the email and password of users
func (cfg *apiConfig) updateUsers(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	usr := user{}
	err := decoder.Decode(&usr)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
		return 
	}

	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Bad credentials"))
		return 
	}

	user_id, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Bad credentials"))
		return
	}

	updated_email := usr.Email
	updated_password := usr.Password
	updated_hashed_password, err := auth.HashPassword(updated_password)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
		return 
	}

	dbParams := database.UpdateUserEmailAndPasswordParams{
		Email: updated_email,
		HashedPassword: updated_hashed_password,
		ID: user_id,
	}

	err = cfg.db.UpdateUserEmailAndPassword(req.Context(), dbParams)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
		return 
	}

	usrDb, err := cfg.db.GetUserById(req.Context(), user_id)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"Something went wrong\"}"))
		return 
	}

	userRes := userResponse{
		ID: usrDb.ID,
		CreatedAt: usrDb.CreatedAt,
		UpdatedAt: usrDb.UpdatedAt,
		Email: usrDb.Email,
		IsChirpyRed: usrDb.IsChirpyRed,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	res, _ := json.Marshal(userRes)
	w.Write(res)
}

//delete chirps handler: deletes a chirp 
func (cfg *apiConfig) DeleteChirps(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Bad credentials!"))
		return 
	}

	user_id, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("Bad credentials!"))
		return 
	}

	chrpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Something went wrong"))
		return 
	}

	chrpDb, err := cfg.db.GetChirp(req.Context(), chrpID)
	if err != nil {
		w.WriteHeader(404)
		w.Write([]byte("Chirp not found"))
		return 
	}

	if user_id != chrpDb.UserID {
		w.WriteHeader(403)
		w.Write([]byte("Chirp not found"))
		return 
	}

	err = cfg.db.DeleteChirp(req.Context(), chrpID)
    if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Something went wrong"))
		return 
	}

	w.WriteHeader(204)
	w.Write([]byte("Chirp deleted successfully!"))
}

//updgrade handler: upgrades a user to chirpy red 
func (cfg *apiConfig) UpgradeUsersToChirpyRed(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	userUpgradedEvent := UserUpgradedEvent{}
	err := decoder.Decode(&userUpgradedEvent)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Something went wrong"))
		return 
	}

	pkey, err := auth.GetPolkaApiKey(req.Header)
	if err != nil || pkey != cfg.polka_key {
		w.WriteHeader(401)
		w.Write([]byte("Bad credentials"))
		return 
	}

	event := userUpgradedEvent.Event
	if event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}

	user_id, err := uuid.Parse(userUpgradedEvent.Data.UserID)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Something went wrong"))
		return 
	}

	_, err = cfg.db.GetUserById(req.Context(), user_id)
	if err != nil {
		w.WriteHeader(404)
		w.Write([]byte("User not found"))
		return 
	}

	err = cfg.db.UpgradeUserToChirpyRed(req.Context(), user_id)
    if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Something went wrong"))
		return 
	}

	w.WriteHeader(204)
}

