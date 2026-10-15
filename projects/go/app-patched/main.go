// Toolshed — the lending service of a neighbourhood workshop.
package main

import (
	"log"
	"net/http"
	"os"

	"toolshed/internal/api"
	"toolshed/internal/store"
)

const Version = "1.4.2"

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	db, err := store.Open(env("TOOLSHED_DB", "var/toolshed.db"))
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	uploads := env("TOOLSHED_UPLOADS", "var/uploads")
	if err := os.MkdirAll(uploads, 0o750); err != nil {
		log.Fatalf("create upload directory: %v", err)
	}

	srv := api.New(db, uploads, Version)
	addr := ":" + env("PORT", "8000")
	log.Printf("toolshed %s listening on %s", Version, addr)
	log.Fatal(http.ListenAndServe(addr, srv.Routes()))
}
