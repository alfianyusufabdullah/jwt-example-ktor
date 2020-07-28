package alfianyusufabdullah.ktor.jwt

import alfianyusufabdullah.ktor.jwt.common.AuthenticationConfig
import alfianyusufabdullah.ktor.jwt.entity.AuthPrinciple
import alfianyusufabdullah.ktor.jwt.entity.User
import alfianyusufabdullah.ktor.jwt.rest.authWidget
import io.ktor.application.Application
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authentication
import io.ktor.auth.jwt.jwt
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.gson.gson
import io.ktor.http.HttpStatusCode
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.util.KtorExperimentalAPI

val ApplicationCall.authPrinciple get() = authentication.principal<AuthPrinciple>()

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@KtorExperimentalAPI
fun Application.module() {

    val jwtRealm = environment.config.property("jwt.realm").getString()

    install(ContentNegotiation) {
        gson {
            setPrettyPrinting()
        }
    }

    install(StatusPages){
        status(HttpStatusCode.Unauthorized){
            call.respond(
                HttpStatusCode.Unauthorized,
                mapOf(
                    "message" to "Unauthorized"
                )
            )
        }
    }

    install(Authentication) {
        jwt {
            realm = jwtRealm
            verifier(AuthenticationConfig.verifier)
            validate {
                val name = it.payload.getClaim("username").asString()
                val password = it.payload.getClaim("password").asString()
                val expired = it.payload.getClaim("expired").asLong()

                if (name != null && password != null) {
                    val user = User(name, password)
                    AuthPrinciple(user, expired)
                } else {
                    null
                }
            }
        }
    }

    install(Routing){
        authWidget()
    }
}