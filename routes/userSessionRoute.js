import { Router } from "express"
const router = new Router()

router.get('/session', (req, res) => {
    return res.send(JSON.stringify(req.session))
})

router.get('/login', (req, res) => {
    res.render('login', {})
})
router.get('/register', (req, res) => {
    res.render('register', {})
})

export default router