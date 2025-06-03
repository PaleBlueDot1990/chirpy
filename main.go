package main 

import (
	"fmt"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	server := http.Server{
		Addr: ":8080",
		Handler: mux,
	}
	
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("Server error: ", err)
	}
}