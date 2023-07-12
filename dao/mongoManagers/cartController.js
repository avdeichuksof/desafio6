import Cart from '../models/cartModel.js'

class CartController{
    constructor(path){
        this.path = path
    }

    async getCarts(){
        try{
            return (
                await Cart.find({})
            )
        }catch(err){
            console.log(err)
        }
    }

    async getCartById(id){
        try{
            const cartFound = await Cart.findOne({_id: id})
            console.log(cartFound)
            if(cartFound){
                return cartFound
            }else{
                console.log({message: 'Cart not found'})
                return null
            }
        }catch(err){
            console.log(err)
        }
    }
    
    addCart(){
        let cart = new Cart()
        return cart.save()
    }
    
    addToCart = async (cartId, prodId) => {
        try{
            let cart = await this.getCartById(cartId)
            
            const productFound = cart.products.find(item => item.product.toString() === prodId)

            if(productFound){
                await Cart.updateOne(
                    {_id: cartId, 'products.product': prodId},
                    {$inc: {'products.$.quantity': 1}}
                )
                return ({message:'Product quantity increased'})
            }else{
                const addProd = {$push:{products:{product: prodId, quantity: 1}}}
                await Cart.updateOne({_id: cartId}, addProd)
                return ({message:'Product added to cart'})
            }
        }catch(err){
            console.log(err)
        }
    }

    updateQuantity = async (cartId, prodId, newQuantity) => {
        try{
            const cartFound = await this.getCartById(cartId)

            if(cartFound){
                const productFound = cartFound.products.find((product) => product.product.toString() === prodId)

                if(productFound){
                    await Cart.updateOne(
                        {_id: cartId, 'products.product': prodId},
                        {$set: {'products.$.quantity': newQuantity}}
                    )
                    return ({message: 'Quantity updated'})
                }else{
                    console.log('Product not found')
                }
            }
        }catch(err){
            console.log(err)
        }
    }

    deleteFromCart = async (cartId, prodId) => {
        try{
            const cartFound = await this.getCartById(cartId)
            if(cartFound){
                const productFound = cartFound.products.findIndex(product => product._id === prodId)
                
                if(productFound){
                    cartFound.products.splice(productFound, 1)
                    await cartFound.save()
                    return cartFound
                }else{
                    return false
                }
            }else{
                console.log('Cart not found')
            }
        }catch(err){
            console.log(err)
        }
    }

    emptyCart = async (cartId) => {
        try{
            const cartFound = await this.getCartById(cartId)
            if(cartFound){
                cartFound.products = []
                await cartFound.save()
                return cartFound
            }else{
                return false
            }
        }catch(err){
            console.log(err)
        }
    }

}


export default CartController