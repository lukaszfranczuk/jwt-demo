package pl.franek.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.RequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import spock.lang.Specification

@SpringBootTest
@WebAppConfiguration
class LoginSpec extends Specification {

    MockMvc mockMvc

    @Autowired
    WebApplicationContext webApplicationContext


    def setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(webApplicationContext)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build()
    }

    def "should return JWT in Authorization header"() {
        given: "mockMvc request builder for /login endpoint with valid credentials in request body"
        String requestPayload = "{\"username\":\"admin\",\"password\":\"adminPwd\"}"
        RequestBuilder requestBuilder = MockMvcRequestBuilders
                .post("/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestPayload)

        when: "we perform request to our endpoint"
        def response = mockMvc.perform(requestBuilder).andReturn().getResponse()

        then: "success response code is returned"
        response.getStatus() == 200

        and: "Authorization header is present with JWT"
        response.getHeader(HttpHeaders.AUTHORIZATION) != null
        response.getHeader(HttpHeaders.AUTHORIZATION).startsWith("Bearer")
    }
}
