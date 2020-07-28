package alfianyusufabdullah.ktor.jwt.common

import alfianyusufabdullah.ktor.jwt.entity.User
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import java.util.*

object AuthenticationConfig {
    private const val secret = "alfianyusufabdullah.ktor.example.SECRET"
    private const val issuer = "alfianyusufabdullah.ktor.example.ISSUER"
    private const val validityInMs = 36_000_00 * 24 * 7

    val verifier: JWTVerifier = JWT
        .require(Algorithm.HMAC256(secret))
        .withIssuer(issuer)
        .build()

    fun generateNewTokenForUser(user: User?): String {
        return JWT.create()
            .withSubject("Authentication")
            .withIssuer(issuer)
            .withClaim("username", user?.username)
            .withClaim("password", user?.password)
            .withClaim("time", System.currentTimeMillis())
            .withExpiresAt(getExpiration())
            .sign(Algorithm.HMAC256(secret))
    }

    private fun getExpiration() = Date(System.currentTimeMillis() + validityInMs)

}