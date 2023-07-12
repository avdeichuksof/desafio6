import passport from 'passport'
import {Router} from 'express'
const router = new Router()

router.get('/', 
    passport.authenticate('github', {scope: ['user: email']})
)

router.get('/callback',
    // si falla la auth
    passport.authenticate('github', {failureRedirect: '/user/login'}),
    // si no falla
    (req, res) => {
        req.session.user = req.user
        res.redirect('/index')
    }
)



export default router