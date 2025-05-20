// Adds the credentials (demo.testfire.net) to the request body
// Needs to be configured with 'Before request' context
if (request.method == "POST") {
    request.body = JSON.stringify({
      "username":"jsmith",
      "password":"demo1234"
    })
  }