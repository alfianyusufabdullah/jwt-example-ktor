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

    fun generateNewTokenForUser(user: User?): Map<String, Any> {
        val expiredDate = getExpiration().time

        val newToken =  JWT.create()
            .withSubject("Authentication")
            .withIssuer(issuer)
            .withClaim("username", user?.username)
            .withClaim("password", user?.password)
            .withClaim("expired", expiredDate)
            .withExpiresAt(getExpiration())
            .sign(Algorithm.HMAC256(secret))

        return mapOf(
            "token" to newToken,
            "created_at" to Date(System.currentTimeMillis()),
            "expired_at" to Date(expiredDate)
        )
    }

    private fun getExpiration() = Date(System.currentTimeMillis() + validityInMs)

}