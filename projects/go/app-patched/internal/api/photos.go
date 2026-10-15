package api

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"toolshed/internal/store"
)

const maxPhotoBytes = 8 << 20

var acceptedExt = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".webp": true}

func randomName(ext string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf) + ext, nil
}

func (s *Server) uploadPhoto(w http.ResponseWriter, r *http.Request, m *store.Member) {
	if err := r.ParseMultipartForm(maxPhotoBytes); err != nil {
		fail(w, http.StatusBadRequest, "no photo")
		return
	}
	src, header, err := r.FormFile("photo")
	if err != nil {
		fail(w, http.StatusBadRequest, "no photo")
		return
	}
	defer src.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !acceptedExt[ext] {
		fail(w, http.StatusBadRequest, "file not accepted")
		return
	}
	name, err := randomName(ext)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot name the photo")
		return
	}
	dst, err := os.OpenFile(filepath.Join(s.Uploads, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot store the photo")
		return
	}
	defer dst.Close()
	if _, err := io.Copy(dst, io.LimitReader(src, maxPhotoBytes)); err != nil {
		fail(w, http.StatusInternalServerError, "cannot store the photo")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": name, "owner": m.Email})
}

func (s *Server) fetchPhoto(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	path := filepath.Join(s.Uploads, name)
	if _, err := os.Stat(path); err != nil {
		fail(w, http.StatusNotFound, "no such photo")
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, path)
}
