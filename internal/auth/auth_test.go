package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const tokenSecret = "test-secret"

func TestMakeAndValidateJWT_Success(t *testing.T) {
	userID := uuid.New()

	// Create JWT
	token, err := MakeJWT(userID, tokenSecret, time.Minute*5)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	// Validate JWT
	parsedID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}

	if parsedID != userID {
		t.Errorf("Expected userID %v, got %v", userID, parsedID)
	}
}

func TestValidateJWT_InvalidSecret(t *testing.T) {
	userID := uuid.New()

	token, err := MakeJWT(userID, tokenSecret, time.Minute*5)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	_, err = ValidateJWT(token, "wrong-secret")
	if err == nil {
		t.Fatal("Expected error for wrong secret, got nil")
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	userID := uuid.New()

	// Token already expired
	token, err := MakeJWT(userID, tokenSecret, -time.Minute*1)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	_, err = ValidateJWT(token, tokenSecret)
	if err == nil {
		t.Fatal("Expected error for expired token, got nil")
	}
}

func TestValidateJWT_InvalidIssuer(t *testing.T) {
	userID := uuid.New()

	// Create token with wrong issuer manually
	claims := jwt.RegisteredClaims{
		Issuer:    "wrong-issuer",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	_, err = ValidateJWT(tokenStr, tokenSecret)
	if err == nil || err.Error() != "invalid issuer" {
		t.Errorf("Expected 'invalid issuer' error, got: %v", err)
	}
}

func TestValidateJWT_InvalidUserID(t *testing.T) {
	// Create token with malformed UUID
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Subject:   "not-a-uuid",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	_, err = ValidateJWT(tokenStr, tokenSecret)
	if err == nil {
		t.Error("Expected error for invalid UUID in subject, got nil")
	}
}
