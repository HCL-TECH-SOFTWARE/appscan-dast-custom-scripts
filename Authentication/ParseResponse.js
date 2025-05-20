// Extract the authorization string from the body
// Assuming that the body is a json with a 'authorization' proeprty as a string
// If so, save the authroization string in the globalVariables
// Needs to be configured with 'After response' context and after the 'AddCredentials' script
try {
    var result = JSON.parse(response.body)
    log(`parsing: ${JSON.parse(response.body).Authorization}`)
    if(result.Authorization) {
      environment.globalVariables.addOrUpdate("Authorization", result.Authorization)
      log(`key = ${result.Authorization}`)
    }
  }
  catch (error) {
    log(error)
  }