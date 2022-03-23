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

type PrivateKey struct {
	crypto.PrivateKey
}
type PublicKey struct {
	crypto.PublicKey
}

type JWT struct {
	*PrivateKey
	*PublicKey
}

func NewPrivateKey() (*PrivateKey, error) {
	parsePrivateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKey)
	if err != nil {
		err = fmt.Errorf("signing token load private-key error: %w", err)
		return nil, err
	}
	return &PrivateKey{parsePrivateKey}, nil
}
func NewPublicKey() (*PublicKey, error) {
	parsePublicKey, err := jwt.ParseEdPublicKeyFromPEM(publicKey)
	if err != nil {
		err = fmt.Errorf("signing token load public-key error: %w", err)
		return nil, err
	}
	return &PublicKey{parsePublicKey}, nil
}
func New() (*JWT, error) {
	privateKey, err := NewPrivateKey()
	if err != nil {
		return nil, err
	}
	publicKey, err := NewPublicKey()
	if err != nil {
		return nil, err
	}
	return &JWT{privateKey, publicKey}, nil

}

type AuthClaims struct {
	UserId int64 `json:"user_id"`
	jwt.RegisteredClaims
}

func (pk *PrivateKey) Sign(userId int64) (tokenString string, err error) {

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
	tokenString, err = token.SignedString(pk.PrivateKey)
	if err != nil {
		err = fmt.Errorf("signing token error: %w", err)
	}
	return
}

func (pk *PublicKey) Parse(tokenString string) (claims *AuthClaims, err error) {

	claims = &AuthClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))
	//parser := jwt.NewParser()
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (key interface{}, err error) {
		return pk.PublicKey, nil
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
