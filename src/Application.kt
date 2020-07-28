package alfianyusufabdullah.ktor.jwt

import alfianyusufabdullah.ktor.jwt.common.AuthenticationConfig
import alfianyusufabdullah.ktor.jwt.entity.AuthPrinciple
import alfianyusufabdullah.ktor.jwt.entity.User
import io.ktor.application.*
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.auth.authentication
import io.ktor.auth.jwt.jwt
import io.ktor.response.*
import io.ktor.request.*
import io.ktor.routing.*
import io.ktor.http.*
import io.ktor.gson.*
import io.ktor.features.*
import io.ktor.client.*
import io.ktor.client.engine.jetty.*
import io.ktor.util.KtorExperimentalAPI
import org.eclipse.jetty.util.log.Log

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

    install(Authentication) {
        jwt {
            realm = jwtRealm
            verifier(AuthenticationConfig.verifier)
            validate {
                val name = it.payload.getClaim("username").asString()
                val password = it.payload.getClaim("password").asString()

                if (name != null && password != null) {
                    val user = User(name, password)
                    AuthPrinciple(user)
                } else {
                    null
                }
            }
        }
    }

    routing {
        authenticate {
            get("/test/request") {
                call.authPrinciple?.let {
                    call.respond(
                        HttpStatusCode.OK,
                        mapOf(
                            "message" to "Success! getting new data.."
                        )
                    )
                } ?: kotlin.run {
                    call.respond(
                        HttpStatusCode.Unauthorized,
                        mapOf(
                            "message" to "error getting information, be sure token included"
                        )
                    )
                }
            }
        }

        post("/auth/login") {
            val user = call.receiveOrNull<User>()
            user?.let {
                val newToken = AuthenticationConfig.generateNewTokenForUser(user)
                call.respond(
                    HttpStatusCode.OK,
                    mapOf(
                        "message" to "Success! Don't tell anyone about your token",
                        "time" to System.currentTimeMillis(),
                        "token" to newToken
                    )
                )
            } ?: kotlin.run {
                call.respond(
                    HttpStatusCode.OK,
                    mapOf(
                        "message" to "login failed! Be sure all information included"
                    )
                )
            }
        }
    }
}

