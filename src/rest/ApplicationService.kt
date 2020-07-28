package alfianyusufabdullah.ktor.jwt.rest

import alfianyusufabdullah.ktor.jwt.authPrinciple
import alfianyusufabdullah.ktor.jwt.common.AuthenticationConfig
import alfianyusufabdullah.ktor.jwt.entity.User
import io.ktor.application.call
import io.ktor.auth.authenticate
import io.ktor.http.HttpStatusCode
import io.ktor.request.receiveOrNull
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import java.util.*

fun Route.authWidget(){
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
                HttpStatusCode.BadRequest,
                mapOf(
                    "message" to "login failed! Be sure all information included"
                )
            )
        }
    }
}