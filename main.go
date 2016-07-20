package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gagliardetto/gzip"
	"github.com/gin-gonic/gin"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/crypto/sha3"
)

var (
	router *gin.Engine

	RECAPTCHA_SECRET   string
	GLOBAL_SIGNING_KEY string
	SERVER_DOMAIN      string
	SERVER_PORT        string // ":8080" in debug mode; "" in production
	SSL_ENABLED        bool   // FALSE in debug mode; TRUE in production
)

const (
	HTTPerror404 = `<html>
<head><title>404 Not Found</title></head>
<body bgcolor="white">
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.7.7</center>
</body>
</html>
`
)

func init() {

	fmt.Println(os.Getenv("RECAPTCHA_SECRET"))
	if len(os.Getenv("RECAPTCHA_SECRET")) > 0 {
		RECAPTCHA_SECRET = os.Getenv("RECAPTCHA_SECRET")
	} else {
		panic("You must set the RECAPTCHA_SECRET environment variable")
	}

	if len(os.Getenv("GLOBAL_SIGNING_KEY")) > 0 {
		GLOBAL_SIGNING_KEY = os.Getenv("GLOBAL_SIGNING_KEY")
	} else {
		panic("You must set the GLOBAL_SIGNING_KEY environment variable")
	}

	if len(os.Getenv("SERVER_DOMAIN")) > 0 {
		SERVER_DOMAIN = os.Getenv("SERVER_DOMAIN")
	} else {
		panic("You must set the SERVER_DOMAIN environment variable")
	}

	if len(os.Getenv("SERVER_PORT")) > 0 {
		SERVER_PORT = os.Getenv("SERVER_PORT")
	} else {
		panic("You must set the SERVER_PORT environment variable")
	}

	if SSLIsEnabled, err := strconv.ParseBool(os.Getenv("SSL_ENABLED")); err == nil {
		SSL_ENABLED = SSLIsEnabled
	} else {
		panic("You must specify whether ssl is enabled or not")
	}

	gin.SetMode(gin.ReleaseMode)
	router = gin.New()
	router.ForwardedByClientIP = true

	router.Use(gin.Recovery())
	router.Use(SecurityMiddleware())
	router.Use(gzip.Gzip(gzip.BestSpeed))

	router.NoRoute(func(cc *gin.Context) {
		cc.Data(404, "text/html", []byte(HTTPerror404))
	})

}

func main() {

	router.Static("/static/", "./static/")

	userRouterGroup := router.Group("/user")
	{
		userRouterGroup.StaticFile("/login", "./pages/user/login.html")
		userRouterGroup.POST("/login", UserLoginPOSTendpoint)

		userRouterGroupAuthorized := userRouterGroup.Group("/r")
		userRouterGroupAuthorized.Use(SessionChecker(true)) // the SessionChecker() middleware checks whether the user is logged in and has the necessary privileges
		{
			userRouterGroupAuthorized.StaticFile("/dashboard", "./pages/user/dashboard.html")
		}
	}

	log.Println("Starting server...")
	if err := router.Run(SERVER_PORT); err != nil {
		panic(err)
	}
}

func UserLoginPOSTendpoint(cc *gin.Context) {
	authenticatePerson(cc)
}
func authenticatePerson(cc *gin.Context) {
	time.Sleep(500 * time.Millisecond)

	recaptchaIsValid, err := VerifyRecaptcha(cc.PostForm("recaptchaTry"))
	if err != nil {
		log.Printf("Error while making call to recaptcha", err)
		cc.IndentedJSON(http.StatusInternalServerError, gin.H{
			"error": "Error, please retry.",
		})
		return
	}
	if recaptchaIsValid != true {
		log.Printf("wrong recaptcha from: %q", cc.ClientIP())
		cc.IndentedJSON(http.StatusNotAcceptable, gin.H{
			"error": "Captcha is not right. Please retry.",
		})
		return
	}

	email := strings.ToLower(strings.Trim(cc.PostForm("email"), " ")) // this is the email the user is trying to login with
	password := strings.Trim(cc.PostForm("password"), " ")            // this is the password the user is trying to login with

	loginCredentialsAreCorrect, err := checkLoginCredentials(email, password)

	if !loginCredentialsAreCorrect || err != nil {
		cc.IndentedJSON(http.StatusNotAcceptable, gin.H{
			"error": "Wrong login data",
		})
		return
	}

	// Create claims for the token
	claims := make(map[string]interface{})
	claims["exp"] = time.Now().Add(time.Hour * 24 * 30).Unix()
	// You can add other claims, too
	claims["user_id"] = "54ef5164-5a1f-4a41-bf26-23838b683963"

	// Set session token
	err = setBearerToken(cc, claims)
	if err != nil {
		cc.IndentedJSON(http.StatusInternalServerError, gin.H{
			"error": "Error, please retry.",
		})
		return
	}

	// Send response with dashboard URL
	cc.IndentedJSON(200, gin.H{
		"response": "Loading dashboard...",
		"url":      "/user/r/dashboard",
	})
}

func checkLoginCredentials(email string, password string) (bool, error) {

	// TODO: check if email is not null and is valid
	// TODO: check if password is not null and is valid

	// TODO: add salt
	emailHasher := sha3.New224()
	emailHasher.Write([]byte(email))
	emailHash := base64.URLEncoding.EncodeToString(emailHasher.Sum(nil))

	passwordHasher := sha3.New224()
	passwordHasher.Write([]byte(password))
	passwordHash := base64.URLEncoding.EncodeToString(passwordHasher.Sum(nil))

	_, _ = emailHash, passwordHash

	// TODO:
	/*
		CHECK IN THE DB HERE
	*/

	return true, nil // Login successful
	//return false, err // Login failed; DO NOT SPECIFY WHAT IS WRONG
}

func setBearerToken(cc *gin.Context, claims map[string]interface{}) error {
	token := jwt.New(jwt.SigningMethodHS256)

	if _, expirationIsSet := claims["exp"]; !expirationIsSet {
		return errors.New("token expiration must be set")
	}

	token.Header["typ"] = "JWT"
	token.Header["iat"] = time.Now().Unix()

	for claimIndex, claimValue := range claims {
		token.Claims[claimIndex] = claimValue
	}

	tts, err := token.SignedString([]byte(GLOBAL_SIGNING_KEY))
	if err != nil {
		return err
	}

	var JWTCookie http.Cookie = http.Cookie{
		Name:     "token",
		Value:    tts,
		Expires:  time.Unix(claims["exp"].(int64), 0),
		Domain:   SERVER_DOMAIN,
		Path:     "/",
		HttpOnly: true,
		Secure:   SSL_ENABLED,
	}
	http.SetCookie(cc.Writer, &JWTCookie)

	return nil
}

// A JSON Web Token middleware
func SessionChecker(redirect_to_login_page bool) gin.HandlerFunc {
	// TODO: add support for Authorization header
	return func(cc *gin.Context) {
		/*
			TODO: check if https; if NOT https, return error
		*/

		bearerTokenStringCookie, err := cc.Request.Cookie("token")
		if err != nil {
			if redirect_to_login_page {
				cc.Redirect(http.StatusTemporaryRedirect, "/user/login")
			} else {
				cc.AbortWithStatus(http.StatusUnauthorized)
			}
			return
		}

		bearerTokenString := bearerTokenStringCookie.Value
		bearerTokenIsNotEmpty := len(bearerTokenString) > 0

		if bearerTokenIsNotEmpty {
			tt, err := jwt.Parse(bearerTokenString, func(token *jwt.Token) (interface{}, error) {

				// Always check the signing method
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}

				// Return the key for validation
				return []byte(GLOBAL_SIGNING_KEY), nil
			})

			expirationDate, expirationIsSet := tt.Claims["exp"].(float64)
			isNotExpired := expirationDate > float64(time.Now().Unix())

			if tt.Valid && expirationIsSet && isNotExpired && err == nil {

				// This user has a valid token, and his/her session is not expired
				fmt.Println("token is VALID and session is NOT expired")

				// Store token claims in gin.Context to make them accessible to endpoints
				cc.Set("claims", tt.Claims)

				userID, userIDIsSet := tt.Claims["user_id"].(string)
				if userIDIsSet {
					fmt.Println("user", userID, "has requested a page")
				}

				cc.Next() //continue

				return // LEAVE THIS HERE
			}
		}

		if redirect_to_login_page {
			cc.Redirect(http.StatusTemporaryRedirect, "/user/login")
		} else {
			cc.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

func SecurityMiddleware() gin.HandlerFunc {
	return func(cc *gin.Context) {
		// <deception>
		cc.Header("X-Powered-By", "PHP/5.5.9-1ubuntu4.5")
		cc.Header("Server", "nginx/1.7.7")
		//TODO: list the headers in the same order nginx lists them
		// </deception>

		// <security>
		cc.Header("X-Content-Type-Options", "nosniff")
		cc.Header("X-Frame-Options", "DENY")
		cc.Header("X-XSS-Protection", "1; mode=block")
		cc.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		// TODO: add content-security-policy header
		// </security>

		// <caching>
		// TODO: differentiate between static and dynamic, user-specific and public content.
		cc.Header("Cache-Control", "private, max-age=0") // <DONOTUSE>no-cache</DONOTUSE>, no-store, must-revalidate, private
		cc.Header("Pragma", "no-cache")
		// </caching>

		// <other>
		cc.Header("Hiring-Now", "Impress us!")
		// </other>

		cc.Next()
	}
}

func VerifyRecaptcha(recaptchaTry string) (bool, error) {
	// TODO: sanitize/check recaptchaTry

	recaptchaRequest := gorequest.New()
	resp, body, errs := recaptchaRequest.Post("https://www.google.com/recaptcha/api/siteverify").
		Send("secret=" + RECAPTCHA_SECRET + "&response=" + recaptchaTry).
		End()
	if errs != nil {
		return false, fmt.Errorf("%v", errs)
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("recaptcha response status code: %v", resp.StatusCode)
	}
	if body == "" || len(body) < 1 {
		return false, errors.New("response body is null while making call to recaptcha")
	}
	recaptchaReponseBodyStruct := struct {
		Success bool
	}{}

	err := json.Unmarshal([]byte(body), &recaptchaReponseBodyStruct)
	if err != nil {
		return false, fmt.Errorf("can't unmarshal recaptchaReponseBodyStruct: %v", err)
	}
	return recaptchaReponseBodyStruct.Success, nil
}
