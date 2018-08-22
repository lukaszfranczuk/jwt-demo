##### JWT DEMO

Very simple application showing example JWT Authentication implementation for REST API

- login endpoint: ``/api/login`` request with payload:
```json
{
	"username": "admin",
	"password": "adminPwd"
}
```
in response you will get token in header ``Authorization``

- example endpoint: ``/api/hello`` with header ``Authorization`` with value from login response