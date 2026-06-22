# Career Auth API — Spring Boot + Redis + JWT

Authentication module for the AI-Powered Career Counselling Platform.
Handles Signup, Login, Token Refresh, and Logout using JWT (access + refresh tokens)
backed by Redis for refresh-token storage, revocation, and login rate-limiting.

## Tech Stack
- Java 17, Spring Boot 3.3
- Spring Security (stateless, JWT-based)
- Redis (refresh token store, access-token blocklist, login attempt limiter)
- Spring Data JPA + H2 (local dev) / PostgreSQL (production)
- jjwt 0.12.6 for JWT generation/validation
- BCrypt for password hashing

## Endpoints

| Method | Path                | Auth required | Description                          |
|--------|---------------------|----------------|---------------------------------------|
| POST   | /api/auth/signup     | No             | Create account, returns token pair    |
| POST   | /api/auth/login      | No             | Login, returns token pair             |
| POST   | /api/auth/refresh    | No (uses refresh token in body) | Issues new token pair |
| POST   | /api/auth/logout     | Yes (Bearer)   | Revokes refresh token + blocklists access token |
| GET    | /api/profile/me      | Yes (Bearer)   | Example protected endpoint            |

### Sample requests

**Signup**
```
POST /api/auth/signup
Content-Type: application/json

{
  "fullName": "Vaishnavi Thanniru",
  "email": "vaishnavi@example.com",
  "password": "StrongPass123"
}
```

**Login**
```
POST /api/auth/login
Content-Type: application/json

{
  "email": "vaishnavi@example.com",
  "password": "StrongPass123"
}
```

**Response (signup/login/refresh)**
```json
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "user": {
    "id": 1,
    "fullName": "Vaishnavi Thanniru",
    "email": "vaishnavi@example.com",
    "role": "USER"
  }
}
```

**Refresh**
```
POST /api/auth/refresh
Content-Type: application/json

{ "refreshToken": "eyJ..." }
```

**Logout**
```
POST /api/auth/logout
Authorization: Bearer <accessToken>
Content-Type: application/json

{ "refreshToken": "eyJ..." }
```

**Calling a protected endpoint**
```
GET /api/profile/me
Authorization: Bearer <accessToken>
```

## Run locally

Requires Java 17, Maven, and Redis running locally (or Docker).

```bash
# Start Redis (if you don't have it installed)
docker run -d -p 6379:6379 redis:7

# Run the app (uses H2 in-memory DB by default, profile = local)
./mvnw spring-boot:run
```

App runs on `http://localhost:8080`. H2 console available at `/h2-console` (JDBC URL: `jdbc:h2:mem:careerdb`).

Test with curl:
```bash
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"fullName":"Test User","email":"test@example.com","password":"password123"}'
```

## Deploying (Render — recommended, free tier)

1. Push this project to a GitHub repo.
2. On Render: **New + > Web Service** → connect your repo.
   - Environment: **Docker** (add a simple Dockerfile, see below) or **Java/Maven** native build.
   - Build command: `./mvnw clean package -DskipTests`
   - Start command: `java -jar target/career-auth-api-1.0.0.jar`
3. Add a **Render Key Value (Redis)** instance — copy its host/port/password.
4. Add a **Render PostgreSQL** instance — copy its connection details.
5. Set environment variables on the web service:
   ```
   SPRING_PROFILES_ACTIVE=prod
   APP_JWT_SECRET=<generate a long random base64 string>
   DATABASE_URL=jdbc:postgresql://<host>:<port>/<dbname>
   DATABASE_USERNAME=<from Render Postgres>
   DATABASE_PASSWORD=<from Render Postgres>
   REDIS_HOST=<from Render Redis>
   REDIS_PORT=<from Render Redis>
   REDIS_PASSWORD=<from Render Redis>
   ```
6. Deploy. Your live base URL will look like:
   ```
   https://career-auth-api.onrender.com
   ```
7. Update CORS allowed origins in `SecurityConfig.java` with your actual Lovable/Netlify frontend URL, redeploy.
8. Give Lovable this URL as `VITE_API_BASE_URL`.

### Optional Dockerfile
```dockerfile
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /app
COPY . .
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/career-auth-api-1.0.0.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

## Frontend integration notes (for Lovable)

- Access token: keep in memory/React state — never localStorage (XSS risk).
- Refresh token: can be kept in memory too for a SPA, or returned as an httpOnly cookie if you later add that flow. For now this implementation returns it in the JSON body for simplicity.
- On a 401 response, call `/api/auth/refresh` with the stored refresh token, then retry the original request with the new access token.
- On logout, call `/api/auth/logout` with the Authorization header + refresh token in body, then clear local state.

## Talking points for interviews
- Stateless authentication using short-lived access tokens + long-lived refresh tokens.
- Refresh token **rotation**: every refresh issues a new refresh token and revokes the old one (prevents replay).
- Redis used for O(1) token revocation lookups — avoids hitting Postgres on every request.
- Access-token **blocklisting** on logout for defense-in-depth, even though JWTs are normally stateless.
- BCrypt password hashing with salt, login attempt rate-limiting via Redis counters.
