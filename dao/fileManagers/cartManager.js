import fs from 'fs'

class CartManager {
    constructor(path) {
        this.path = path
        this.carts = []
        this.products = []
    }

    #read(){
        try{
            this.carts = JSON.parse(fs.readFileSync(this.path, 'utf-8'))
        }catch(err){
            console.log('File not found.')
        }
    }

    #write(){
        try{
            fs.writeFileSync(this.path, JSON.stringify(this.carts, null, 2), 'utf-8')
        }  
        catch{
            console.log("Error writing file")
        }
    }

    addCart(){
        //leemos el array de carritos
        this.#read()
        //creamos un id único
        const cartId = this.carts.length == 0 ? 1 : this.carts[this.carts.length - 1].id +1
        //creamos el carrito
        const cart = {id: cartId, products: this.products}
        this.carts.push(cart)
        this.#write()
        console.log('Cart created successfully')
        return cart
    }

    getCartById(id){
        this.#read()
        const cartFound = this.carts.find(cart => cart.id === id)
        if(cartFound){
            return cartFound
        }else{
            console.log('Cart not found')
        }
    }

    addProductToCart(cartId, productId){
        this.#read()
        // verificamos si existe el carrito
        const cartFound = this.getCartById(cartId)
        if(!cartFound){
            console.log('Cart not found')
        }else{
            // verificamos si el prod ya está en el carrito
            const productFound = this.products.find(product => product.id === productId)
            
            if(productFound){
                //si existe aumentamos la cantidad
                productFound.quantity += quantity
                this.#write()
                console.log('Product added successfully')
                return productFound
            }else{
                // si no existe lo agregamos
                const newProduct = {id: productId, quantity: 1}
                cartFound.products.push({product: newProduct})
                this.#write()
                console.log('Product added successfully')
                return newProduct
            }
        }
        
    }

}

export default {CartManager}