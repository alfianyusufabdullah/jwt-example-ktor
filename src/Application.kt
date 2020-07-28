package alfianyusufabdullah.ktor.jwt

import alfianyusufabdullah.ktor.jwt.common.AuthenticationConfig
import alfianyusufabdullah.ktor.jwt.entity.AuthPrinciple
import alfianyusufabdullah.ktor.jwt.entity.User
import io.ktor.application.Application
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.auth.authentication
import io.ktor.auth.jwt.jwt
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.gson.gson
import io.ktor.http.HttpStatusCode
import io.ktor.request.receiveOrNull
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import java.util.*

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

    routing {
        authenticate {
            get("/expired") {
                call.authPrinciple?.let {
                    val date = Date(it.expired)
                    call.respond(
                        HttpStatusCode.OK,
                        mapOf(
                            "message" to "success!",
                            "expired_at" to date
                        )
                    )
                }
            }

            get("/test/request") {
                call.authPrinciple?.let {
                    call.respond(
                        HttpStatusCode.OK,
                        mapOf(
                            "message" to "Success! getting new data.."
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
                        "created_at" to newToken["created_at"],
                        "expired_at" to newToken["expired_at"],
                        "token" to newToken["token"]
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

