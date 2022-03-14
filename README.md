# Auth example
### in this project you will see how we can create a authentication mechanism using jwt (json web token)

## What Is Authentication?
Authentication is the process of identifying users that request access to a system, network, or device. 
Access control often determines user identity according to credentials like username and password. 
User authentication is a method that keeps unauthorized users from accessing sensitive information. 
For example, User A only has access to relevant information and cannot see the sensitive information of User B. 

In our example, the server have 2 controllers: auth and secret and our client have coresponding routs.
We want to prevent unauthenticated individuals to access our secert controller and route.

## server

1. we configured the jwt at startup.cs in the server
``` c#
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
              .AddJwtBearer(options =>
              {
                  options.TokenValidationParameters = new TokenValidationParameters
                  {
                      ValidateIssuer = true,
                      ValidateAudience = true,
                      ValidateLifetime = true,
                      ValidateIssuerSigningKey = true,
                      ValidIssuer = Configuration["Jwt:Issuer"],
                      ValidAudience = Configuration["Jwt:Issuer"],
                      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]))
                  };
              });
```
##### Note that we provieded certain jwt data like issuer and key from appsettings.json
``` json
  "Jwt": {
    "Key": "this is my custom Secret key for authnetication",
    "Issuer": "Test.com"
  }
```
2. after we configured the jwt, we can use the `[Authorize]` atrribute on each controller or action we wish to protect
 ``` c#
  [Authorize]
    public class SecretController : ControllerBase{ ... }
```
3. we added sign up or login actions where users can be identify and receive a tokan that expires in 5 minutes
 ``` c#
  public string CreateToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[] {
            new Claim(ClaimTypes.Name, user.Id),
            new Claim(ClaimTypes.Role, user.Role),
        };
            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
              _config["Jwt:Issuer"],
              claims,
              expires: DateTime.Now.AddMinutes(5),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
```
##### Note that each user have a role (part of authorization)
4. we craeted an action that will help us to decode the the token and get back the user id so we can retrive specific data just for him
``` c#
  [TypeFilter(typeof(GetUserActionFilter))]
        public IActionResult Authenticated(){...}
        
        
        public class GetUserActionFilter : ActionFilterAttribute
    {

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            var token = context.HttpContext.Request.Headers.Where(header => header.Key == "Authorization").SingleOrDefault().Value.ToString().Split(" ")[1];
            var user = _userRepository.GetById(_tokenService.GetPayload(token));
            context.HttpContext.Request.RouteValues.Add("user", user);
        }
    }
}
```

## Client

1. in the client we save the token we get from the server and sending it back with each request with the Authorization header
``` typescript
 login(user: User): void {
    const currentUrl = `${this.url}Auth/Login`;
    this.subs.push(
      this.http.post<any>(currentUrl, user).subscribe((res) => {
        this.setToken(res.token);
        this.router.navigateByUrl('/Secret');
      })
    );
  }
  
    secret(): Observable<any> {
    const headers = new HttpHeaders({
      Authorization: 'Bearer ' + this.getToken(),
    });
    const auth$ = this.http
      .get<any>(currentUrl + 'Authenticated', { headers })
      }
     }
     
    private getToken(): string | null {
    return sessionStorage.getItem('token');
  }
  
  private setToken(token: string): void {
    sessionStorage.setItem('token', token);
  }
```
2. additionally, we gurded the secret route in such way that you can only access it if authenticated
``` typescript
// app-routing.ts
const routes: Routes = [
  {
    path: `Secret`,
    component: SecretComponent,
    canActivate: [SecretGuard],
  },
  { path: `SignUp`, component: SignUpComponent },
  { path: `Login`, component: LoginComponent },
  { path: ``, component: LoginComponent },
  { path: `**`, component: LoginComponent },
];

//secret.guard.ts
export class SecretGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}
  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ):
    | Observable<boolean | UrlTree>
    | Promise<boolean | UrlTree>
    | boolean
    | UrlTree {
    return this.authService.checkAccess().pipe(
      map((res) => {
        if (!res) {
          return this.router.parseUrl('/Login');
        } else {
          return res;
        }
      })
    );
  }
}
```
