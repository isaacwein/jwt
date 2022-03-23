# jwt demo
just a demo project how to use jwt sign and parse
its based out of the library [golang-jwt v4](github.com/golang-jwt/jwt)

### Demos
#### Setup
```go
// this is enough one time in the hole project 
JWT, err := jwt.New()
if err != nil {
    // handle error
}
```

#### Sign Token
```go
token, err := JWT.Sign(123456)
if err != nil {
	// handle error
}
```
#### Parse Token

```go
claims, err := JWT.Parse(token)
if err != nil {
    // handle error	
}
```


