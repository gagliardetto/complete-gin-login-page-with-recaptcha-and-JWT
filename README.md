## Complete Golang Gin login page with Recaptcha and JWT

### Installation

Get your recaptcha keys:
+ Visit https://www.google.com/recaptcha/admin#list
+ Add a label (e.g. "example.com's recaptcha")
+ Add domains (e.g. "127.0.0.1" and/or "example.com")

Now you have a "site key" and a "secret key".


On your console, set the environment variables:
```bash
$ export RECAPTCHA_SECRET=your-google-recaptcha-secret-key
$ export GLOBAL_SIGNING_KEY=your-supersecret-signing-key
$ export SERVER_DOMAIN=127.0.0.1
$ export SERVER_PORT=:8080 # ":8080" in debug mode; "" in production
$ export SSL_ENABLED=false # false in debug mode; true in production
```

Inside `login.html` (line 140), add your site key (`data-sitekey`) value.

Inside `main.go`, inside the `checkLoginCredentials` function, add a call to your db to validate the user and password.


Run
```
go run main.go
```

In your browser:
+ Go to http://127.0.0.1:8080/user/login
+ Click on "I'm not a robot"
+ Solve the puzzle (if prompted)
+ Enter any email and password
+ Click on the "Login" button
+ Wait to be redirected to http://127.0.0.1:8080/user/r/dashboard