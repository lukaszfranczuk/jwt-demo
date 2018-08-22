package pl.franek.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpHeaders
import spock.lang.Specification

import javax.servlet.http.HttpServletRequest

@SpringBootTest
class JwtServiceSpec extends Specification {

    @Autowired
    JwtService jwtService

    def "should create JWT from username and role"() {
        given: "username and roles of test user"
        def username = "testUser"
        def roles = "testRole1,testRole2"


        when: "we want to create new JWT token"
        def jwt = jwtService.createJwt(username, roles)

        then: "token is not null"
        jwt != null
    }

    def "should return Authentication object from request with token"() {
        given: "JWT token"
        def jwt = jwtService.createJwt("testUser", "testRole1,testRole2")

        and: "HttpServletRequest with header Authorization containing JWT"
        HttpServletRequest httpServletRequest = Mock(HttpServletRequest.class)
        httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION) >> jwt

        when: "We want to get authentication object from HttpServletRequest"
        def authentication = jwtService.getAuthentication(httpServletRequest)

        then: "authentication object is not null"
        authentication != null

        and: "name in authentication object is the same as one in JWT token"
        authentication.getName() == "testUser"
    }
}
