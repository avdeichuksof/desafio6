import {Router} from 'express'
const router = new Router()
import User from'../dao/models/userModel.js'
import jwt from 'jsonwebtoken'
import passport from'passport'

function auth(req, res, next){
    if(req.session.email === 'adminCoder@coder.com' && req.session.password === 'admin1234'){
        return next()
    }
    return res.send('An error ocurred or you are not an admin ')
}

router.post('/register', passport.authenticate('register', {failureRedirect: '/failedregistration'}), async (req, res) => {
    if(!req.user){
        return res.json({error: 'Something went wrong'})
    }
    req.session.user = {_id: req.user._id, email: req.user.email, firstName: req.user.firstName, password: req.session.password}
    return res.redirect('/user/login')
})

router.get('/failedregistration', async(req, res) => {
    return res.json({error: 'Failed to register'})
})

router.post('/login', passport.authenticate('login', {failureRedirect: '/failedlogin'}), async (req, res) => {
    if(!req.user){
        return res.json({error: 'Invalid credentials'})
    }
    req.session.user = {_id: req.user._id, email: req.user.email, firstName: req.user.firstName, password: req.session.password}
    console.log(req.session.user)

    let token = jwt.sign(req.session.user, 'tokenSecreto', {expiresIn: '2000s'})
    console.log({token, message: 'User logged in'})

    return res.redirect('/index')
})

router.get('/failedlogin', async (req, res) => {
    return res.json({ error: 'Failed to login' })
})

// se puede entrar solo después de loggearse como admin
router.get('/privado', auth, (req, res) => {
    res.send('Bienvenido admin!')
})

router.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if(err) res.send('Failed logout')
        res.redirect('/user/login')
    })
})

router.get('/users', async (req, res) => {
    try{
        const users = await User.find().lean().exec()
        res.send(users)
    }catch(err){
        console.log(err)
    }
})

export default router