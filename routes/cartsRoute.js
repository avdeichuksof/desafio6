import { Router } from 'express'
const router = new Router()
import CartController from '../dao/mongoManagers/cartController.js'
const cartManager = new CartController()
import Cart from '../dao/models/cartModel.js'

router.get('/', async(req, res) => {
    await cartManager.getCarts()
        .then(carts => {
            if(carts.length) return res.status(200).send({data: carts})
            return res.status(204).send({message: 'Data not found'})
        })
        .catch(err => res.status(500).send({err}))
})

router.get('/:cid', (req, res) => {
    const cid = req.params.cid
    const cart = cartManager.getCartById(cid)

    if(cart) Cart.find().populate('products.product')
        .then(c => res.send({cart: JSON.stringify(c)}))
        .catch(err => console.log(err))

})

router.post('/', (req, res) => {
    const cart = new Cart()
    cartManager.addCart(cart)
        .then(cart => 
            res.send({message: 'Cart created successfully', data: cart}
        ))
        .catch(err => res.status(500).send({err}))
})

router.post('/:cid/product/:pid', async (req, res) => {
    const cid = req.params.cid
    const pid = req.params.pid
    const productAdd = await cartManager.addToCart(cid, pid)
    return res.status(200).send({message: 'Product added to cart', product: productAdd})
})

router.put('/:cid', (req, res) => {

})

router.put('/:cid/products/:pid', async (req, res) => {
    const cid = req.params.cid
    const pid = req.params.pid
    const newQuantity = req.body.quantity
    const updateQuant = await cartManager.updateQuantity(cid, pid, newQuantity)
    if (updateQuant) {
        return res.status(200).json({ message: 'Product quantity updated successfully', updateQuant });
    } else {
        return res.status(404).json({ message: 'Product not found' });
    }
})

router.delete('/:cid', async (req, res) => {
    const cid = req.params.cid
    const emptyCart = await cartManager.emptyCart(cid)
    return emptyCart ? res.status(200).send({message: 'Cart is empty'}) : res.status(500).send({err})
})

router.delete('/:cid/products/:pid', async (req, res) => {
    const cid = req.params.cid
    const pid = req.params.pid
    const deleteFromCart = await cartManager.deleteFromCart(cid, pid)
    return deleteFromCart ? res.status(200).send({message: 'Product deleted from cart'}) : res.status(500).send({err})
})

export default router