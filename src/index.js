require("dotenv").config()
const express = require("express")
const cookieParser = require("cookie-parser")
const cors = require("cors")
const { verify } = require("jsonwebtoken")
const { hash, compare } = require("bcryptjs")
const { createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken } = require("./tokens")

const { fakeDB } = require("./fakeDB")
const { appError } = require("./appError")
const {isAuth} = require("./isAuth")
const { path } = require("express/lib/application")

const server = express()
server.use(cookieParser())
server.use(
  cors({
    origin: `http://localhost:${process.env.FRONT_PORT}`,
    credentials: true
  })
)

server.use(express.json())
server.use(express.urlencoded({ extended: true }))

server.listen(process.env.SERVER_PORT, () => {
  console.log(`Server listening on port ${process.env.SERVER_PORT}`)
})

server.post("/register", async (req, res) => {
  const { email, password } = req.body
  try {
    const user = fakeDB.find(user => user.email === email)
    if (user) throw appError(400, "User already exist")
    const hashedPassword = await hash(password, 10)
    fakeDB.push({
      id: fakeDB.length,
      email: email,
      password: hashedPassword
    })
    console.log("User added", fakeDB)
    res.send({ message: "User created" })
  } catch (err) {
    res.status(err.code || 500).send({
      error: err.message
    })
  }
})

server.post("/login", async (req, res) => {
  const { email, password } = req.body
  try {
    const user = fakeDB.find(user => user.email === email)
    if (!user) throw appError(400, "User does not exist")
    const valid = await compare(password, user.password)
    if (!valid) throw appError(403, "Password not correct")

    const accessToken = createAccessToken(user.id)
    const refreshToken = createRefreshToken(user.id)

    user.refreshToken = refreshToken
    console.log(fakeDB)
    // Send refreshToken as a cookie and accessToken as a regular response
    sendRefreshToken(res, refreshToken)
    sendAccessToken(req, res, accessToken)

  } catch (err) {
    res.status(err.code || 500).send({
      error: err.message
    })
  }
})

server.post("/logout", (req, res) => {
  res.clearCookie(process.env.REFRESH_TOKEN_COOKIE_NAME, {path: "/refresh"})
  res.send({
    message: "Logged out"
  })
})

server.post("/protected", async(req,res) => {
  try {
    const userId = isAuth(req)
    if(userId !== null) {
      res.send({
        data: "This is protected data"
      })
    }
  } catch (err) {
    res.status(err.code || 500).send({
      error: err.message
    })
  }
})

server.post("/refresh", (req, res) => {
  const token = req.cookies[process.env.REFRESH_TOKEN_COOKIE_NAME]
  if(!token) return res.send({accessToken: ""})
  let payload
  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET)
  } catch (err) {
    return res.send({accessToken: ""})
  }
  const user = fakeDB.find(user => user.id === payload.userId)
  if (!user) return res.send({accessToken: ""})
  if(user.refreshToken !== token) return res.send({accessToken: ""})
  const accessToken = createAccessToken(user.id)
  const refreshToken = createRefreshToken(user.id)
  user.refreshToken = refreshToken
  sendRefreshToken(res, refreshToken)
  return res.send({accessToken})
})