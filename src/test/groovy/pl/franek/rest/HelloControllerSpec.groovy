package pl.franek.rest

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.RequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import pl.franek.security.JwtService
import spock.lang.Specification

@SpringBootTest
@WebAppConfiguration
class HelloControllerSpec extends Specification {

    MockMvc mockMvc

    @Autowired
    WebApplicationContext webApplicationContext

    @Autowired
    JwtService jwtService


    def setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(webApplicationContext)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build()
    }

    def "should return 403 when request without token"() {
        given: "mockMvc request builder for /hello endpoint without Authorization header"
        RequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/hello")

        when: "we perform request to our endpoint"
        def response = mockMvc.perform(requestBuilder).andReturn().getResponse()

        then: "AccessDenied http status code is returned"
        response.getStatus() == 403
    }

    def "should return 403 when request with expired token"() {
        given: "mockMvc request builder for /hello endpoint with Authorization header containing expired JWT"
        RequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/hello")
                .header("Authorization", "Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjoiUk9MRV9VU0VSIiwiaWF0IjoxNTM0OTYxNDA0LCJleHAiOjE1MzQ5NjI2MDR9.BKJFOn_wAutvuAgTFg4Wmopr_EAQzonx0fGwATgoNWmHGdzgReRv79axSR0HIcI0b2_hCcL-Xwi_hRR-dekz8g")

        when: "we perform request to our endpoint"
        def response = mockMvc.perform(requestBuilder).andReturn().getResponse()

        then: "AccessDenied http status code is returned"
        response.getStatus() == 403
    }

    def "should return success response with body"() {
        given: "mockMvc request builder for /hello endpoint with Authorization header containing valid JWT"
        String jwt = jwtService.createJwt("testUser", "testRole1,testRole2")
        RequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/hello")
                .header("Authorization", "Bearer ".concat(jwt))

        when: "we perform request to our endpoint"
        def response = mockMvc.perform(requestBuilder).andReturn().getResponse()

        then: "response body and success http code is returned"
        response.getStatus() == 200
        response.getContentAsString() == "Hello Secured World"
    }
}
