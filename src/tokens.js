const {sign} = require("jsonwebtoken")
const createAccessToken = userId => {
  return sign({userId}, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m"
  })
}
const createRefreshToken = userId => {
  return sign({userId, }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d"
  })
}

const sendAccessToken = (req, res, accessToken) => {
  res.send({
    accessToken,
    email: req.body.email
  })
}
const sendRefreshToken = (res, refreshToken) => {
  res.cookie(process.env.REFRESH_TOKEN_COOKIE_NAME, refreshToken, {
    httpOnly: true,
    path: "/refresh"
  })
}

module.exports = {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken
}