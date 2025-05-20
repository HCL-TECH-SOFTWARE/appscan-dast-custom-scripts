// Gets the saved authorization from the globalVariables
// if exists, add to the request headers.
// Needs to be configured with 'Before request' context and after the 'ParseResponse' script
var authorization = environment.globalVariables.get("Authorization")
if(authorization) {
  request.headers.set("Authorization", authorization)
  log(`authorization is ${authorization}`)
}