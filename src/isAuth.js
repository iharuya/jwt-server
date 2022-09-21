const {appError} = require("./appError")
const {verify} = require("jsonwebtoken")
const isAuth = req => {
  const authorization = req.headers["authorization"]
  if (!authorization) throw appError(401, "You need to login") 
  const token = authorization.split(" ")[1] // authorization: 'Bearer xxxxx'
  const {userId} = verify(token, process.env.ACCESS_TOKEN_SECRET)
  return userId
}

module.exports = {
  isAuth
}