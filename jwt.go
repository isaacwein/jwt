package jwt

import (
	"crypto"
	_ "embed"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

var (
	//go:embed ed25519.private.pem
	privateKey []byte
	//go:embed ed25519.public.pem
	publicKey []byte
)

type JWT struct {
	parsePrivateKey crypto.PrivateKey
	parsePublicKey  crypto.PrivateKey
}

func New() (*JWT, error) {

	parsePrivateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKey)
	if err != nil {
		err = fmt.Errorf("signing token load private-key error: %w", err)
		return nil, err
	}
	parsePublicKey, err := jwt.ParseEdPublicKeyFromPEM(publicKey)
	if err != nil {
		err = fmt.Errorf("signing token load public-key error: %w", err)
		return nil, err
	}
	return &JWT{parsePrivateKey, parsePublicKey}, nil
}

type AuthClaims struct {
	UserId int64 `json:"user_id"`
	jwt.RegisteredClaims
}

func (JWT *JWT) Sign(userId int64) (tokenString string, err error) {

	// Create the Claims
	claims := &AuthClaims{
		userId,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(3 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "Telebroad LLC",
			Subject:   "test project",
			ID:        fmt.Sprint(userId),
			//Audience: []string{"somebody_else"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	fmt.Printf("SigningMethod: %#+v\n", token.Method)
	tokenString, err = token.SignedString(JWT.parsePrivateKey)
	if err != nil {
		err = fmt.Errorf("signing token error: %w", err)
	}
	return
}

func (JWT *JWT) Parse(tokenString string) (claims *AuthClaims, err error) {

	claims = &AuthClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))
	//parser := jwt.NewParser()
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (key interface{}, err error) {
		return JWT.parsePublicKey, nil
	})
	if err == jwt.ErrTokenExpired {
		return
	}
	if err != nil {
		err = fmt.Errorf("jwt parse error: %w", err)
		return
	}

	if !token.Valid {
		err = fmt.Errorf("jwt invalid")
	}
	return
}
