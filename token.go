package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
)

var (
	AcceptedClaims []string
	KeySet         jwk.Set
	Expiry         int
)

func initKeyset() error {
	var err error
	claims := os.Getenv("CLAIMS")
	if len(claims) > 0 {
		AcceptedClaims = strings.Split(os.Getenv("CLAIMS"), ",")
	} else {
		AcceptedClaims = make([]string, 0)
	}
	KeySet, err = jwk.Parse([]byte(os.Getenv("JWTKS")))
	if err != nil {
		return fmt.Errorf("Issue with JWTKS %v", err)
	}
	Expiry, err = strconv.Atoi(os.Getenv("EXPIRY"))
	if err != nil {
		return fmt.Errorf("Issue with EXPIRY %v", err)
	}
	AcceptedClaims = append(AcceptedClaims, "aud")
	return nil
}

func issueToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fmt.Printf("Bad Method %s\n", r.Method)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		fmt.Printf("Bad Content Type %s\n", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	incoming, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("Bad Body Read\n")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	claims_decls := make(map[string]string)
	err = json.Unmarshal(incoming, &claims_decls)
	if err != nil {
		fmt.Printf("Bad Body parse\n")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	numkeys := KeySet.Len()
	if numkeys < 1 {
		fmt.Printf("Bad Keyset\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	signingKey, keyok := KeySet.Get(numkeys - 1)
	if !keyok {
		fmt.Printf("Bad Keyset Count\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	claims := jwt.MapClaims{
		"iat": jwt.NewNumericDate(time.Now()),
		"exp": jwt.NewNumericDate(time.Now().Add(time.Duration(Expiry) * time.Second)),
		"nbf": jwt.NewNumericDate(time.Now()),
		"id":  uuid.NewString(),
		"iss": os.Getenv("ISSUER"),
	}
	for _, c := range AcceptedClaims {
		v, cok := claims_decls[c]
		if !cok {
			fmt.Printf("Request does not include value for claim %s %+v\n", c, AcceptedClaims)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims[c] = v
		delete(claims_decls, c)
	}
	if len(claims_decls) > 0 {
		fmt.Printf("too many incoming claims %+v\n", claims_decls)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	smethod := jwt.GetSigningMethod(signingKey.Algorithm())
	token := jwt.NewWithClaims(smethod, claims)
	token.Header["kid"] = signingKey.KeyID()
	var raw interface{}
	signingKey.Raw(&raw)
	signed, err := token.SignedString(raw)
	if err != nil {
		fmt.Printf("Signing Error %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/jwt")
	w.Write([]byte(signed))
}
