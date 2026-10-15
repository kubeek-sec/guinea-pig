// Package auth issues and reads the bearer tokens of a member session.
package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"toolshed/internal/store"
)

type ctxKey struct{}

// MemberKey carries the signed-in member through the request context.
var MemberKey = ctxKey{}

var ErrNoKey = errors.New("TOOLSHED_TOKEN_KEY is not set")

func signingKey() ([]byte, error) {
	key := os.Getenv("TOOLSHED_TOKEN_KEY")
	if key == "" {
		return nil, ErrNoKey
	}
	return []byte(key), nil
}

func ttl() time.Duration {
	if v, err := strconv.Atoi(os.Getenv("TOOLSHED_TOKEN_TTL")); err == nil && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Hour
}

// Issue signs a token for the given member.
func Issue(m *store.Member) (string, error) {
	key, err := signingKey()
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   strconv.FormatInt(m.ID, 10),
		"email": m.Email,
		"role":  m.Role,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl()).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
}

// Authenticate looks a member up by email and compares the given password.
func Authenticate(db *sql.DB, email, password string) (*store.Member, error) {
	var m store.Member
	err := db.QueryRow(
		"SELECT id, email, full_name, password, role FROM members WHERE email = ?", email).
		Scan(&m.ID, &m.Email, &m.FullName, &m.Password, &m.Role)
	if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(m.Password), []byte(password)) != nil {
		return nil, errors.New("bad credentials")
	}
	return &m, nil
}

// FromRequest resolves the member behind the Authorization header, if any.
func FromRequest(db *sql.DB, r *http.Request) *store.Member {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return nil
	}
	key, err := signingKey()
	if err != nil {
		return nil
	}
	token, err := jwt.Parse(strings.TrimPrefix(header, "Bearer "),
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return key, nil
		})
	if err != nil || !token.Valid {
		return nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}
	var m store.Member
	err = db.QueryRow(
		"SELECT id, email, full_name, password, role FROM members WHERE id = ?", claims["sub"]).
		Scan(&m.ID, &m.Email, &m.FullName, &m.Password, &m.Role)
	if err != nil {
		return nil
	}
	return &m
}
