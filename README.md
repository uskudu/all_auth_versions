**ALL WAYS TO AUTHENTICATE WITH GIN, GO**

**token based authentication**
1. execute `/token/login`
2. copy token string
3. go to web dev tools (f12), console
4. type: allow paste
5. type: `localStorage.setItem("token", <token_string_from_login_endpoint>)`
6. type: 
```
   fetch("/token/secure", {
       headers: {
           "Authorization": "Bearer " + localStorage.getItem("token")
       }
   })
   .then(res => res.json())
   .then(console.log)
   ```
7. you have reached the secured endpoint.