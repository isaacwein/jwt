package jwt

import (
	"testing"
)

func TestJWT_Sign(t *testing.T) {
	// preparing jwt
	JWT, err := New()
	if err != nil {
		t.Fatalf("jwt setup error: %s", err.Error())
		return
	}

	token, err := JWT.Sign(123456)
	if err != nil {
		t.Fatalf("sign error: %s", err.Error())
		return
	}
	t.Logf("token: \n%s\n", token)
}

func TestJWT_Parse(t *testing.T) {

	// preparing jwt
	JWT, err := New()
	if err != nil {
		t.Fatalf("jwt setup error: %s", err.Error())
		return
	}

	const token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTYsImlzcy" +
		"I6IlRlbGVicm9hZCBMTEMiLCJzdWIiOiJTaXBweSBQcm94eSIsImV4cCI6MTY0ODI2NDAwMiwibmJ" +
		"mIjoxNjQ4MDA0ODAyLCJpYXQiOjE2NDgwMDQ4MDIsImp0aSI6IjEyMzQ1NiJ9.BHvXxis1QptK2Hh" +
		"LaGC0u9IUaS9UUiZ3kRs_ygiJgG9pZkhPJKJFG-XqT_WbA2P9Z-lDaG_p2RxSctocYdk3CQ"
	claims, err := JWT.Parse(token)
	if err != nil {
		t.Fatalf("sign error: %s", err.Error())
		return
	}
	t.Logf("claims: %#+v", claims)
}
