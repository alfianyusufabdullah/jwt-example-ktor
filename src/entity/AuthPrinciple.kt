package alfianyusufabdullah.ktor.jwt.entity

import io.ktor.auth.Principal

class AuthPrinciple(val user: User, val expired: Long) : Principal