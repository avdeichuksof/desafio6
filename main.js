import dotenv from 'dotenv'
dotenv.config()

// server
import express from 'express'
const app = express()
const PORT = 8080 || process.env.PORT

// dependencies
import passport from 'passport'
import session from 'express-session'
import MongoStore from 'connect-mongo'
import handlebars from 'express-handlebars'
import initPassport from './passport/passportConfig.js'

// http import
import http from 'http'
const server = http.createServer(app)

// socket import
import {Server} from 'socket.io'
const io = new Server(server)

// mongo
import db from './dao/mongoManagers/db.js'
import Product from './dao/models/productModel.js'
import Message from './dao/models/messageModel.js'
import ProductManager from './dao/mongoManagers/productController.js'
const PM = new ProductManager()

// routes
import authRoute from './routes/authRoute.js'
import chatRoute from './routes/chatRoute.js'
import cartsRoute from './routes/cartsRoute.js'
import indexRoute from './routes/indexRoute.js'
import githubAuthRoute from './routes/github.js'
import productsRoute from './routes/productsRoute.js'
import realTimeRoute from './routes/realTimeRoute.js'
import userSessionRoute from './routes/userSessionRoute.js'

// passport
initPassport()
app.use(passport.initialize())

// data
app.use(express.json())
app.use(express.urlencoded({extended: true}))

// dirname
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname + '/public'))

// views
app.engine('handlebars', handlebars.engine())
app.set('view engine', 'handlebars')
app.set('views', __dirname + '/views')

// session
app.use(session({
    store: MongoStore.create({
        mongoUrl: db.URL
    }),
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}))

// routes
app.use('/auth', authRoute)
app.use('/chat', chatRoute) // muestra el chat
app.use('/auth/github', githubAuthRoute) // autenticación con github
app.use('/index', indexRoute) // muestra todos los productos
app.use('/api/carts', cartsRoute) // manejador de carritos
app.use('/user', userSessionRoute) // session manager 
app.use('/api/products', productsRoute) // manejador de productos
app.use('/realtimeproducts', realTimeRoute) // agregar y eliminar productos en tiempo real

// sockets
io.on('connection', async (socket) => {
    console.log('User connected')

    // PRODUCTS
    // mostramos todos los productos
    const products = await PM.getProducts()
    socket.emit('products', products)

    socket.on('newProduct', async (data) => {
        console.log(data)
        const newProduct = new Product(data)
        PM.addProduct(newProduct)
        const products = await PM.getProducts()
        io.sockets.emit('all-products', products)
    })

    socket.on('deleteProduct', async (data) => {
        await PM.deleteProduct(data)
        const products = await PM.getProducts()
        io.sockets.emit('all-products', products)
    })

    // CHAT
    const messages = await Message.find()
    socket.on('newMessage', async (data) => {
        const message = new Message(data)
        await message.save(data)
        io.sockets.emit('all-messages', messages)
    })
})

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    db.connect()
})