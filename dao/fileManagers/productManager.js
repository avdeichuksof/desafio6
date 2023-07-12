import fs from 'fs'
import uuid4 from 'uuid4'

class ProductManager {
    constructor(path){
        this.path = path
        this.products = []
    }

    #validateFields(product){
        const keys = ['title',  'description', 'price', 'thumbnail', 'code', 'stock', 'status', 'category']
        const keysInProd = Object.keys(product)
        let error = false
        keys.forEach(key => {
            const included = keysInProd.includes(key)
            if(!included){
                error == true
                console.log('EROR: all fields must be included')
            }
        })
        return error
    }

    #read(){
        try{
            this.products = JSON.parse(fs.readFileSync(this.path, 'utf-8'))
        }catch(err){
            console.log('File not found.')
        }
    }

    #write(){
        try{
            fs.writeFileSync(this.path, JSON.stringify(this.products, null, 2), 'utf-8')
        }
        catch{
            console.log("Error writing file")
        }
    }

    
    addProduct(newProduct, id){
        //leemos el archivo y si no existe lo crea
        this.#read()

        //validamos campos y que no haya un producto con ese código
        const validated = this.#validateFields(newProduct)
        const productFound = this.products.find(product => product.code === newProduct.code)

        if(validated){
            console.log('ERROR all fields needed')
        }else if(productFound){
            console.log('ERROR: product code already exists')
        }else{
            //id autogenerado 
            const newID = uuid4()
            newProduct.id = newID
            //agregamos al array de productos
            this.products.push({...newProduct, id: newProduct.id})
            //escribimos el prod en el JSON
            this.#write()
            console.log('Product added successfully')
            return newProduct
        }
    }

    getProducts(){
        try{
            //leemos el JSON y retornamos lo que tiene
            const products = fs.readFileSync(this.path, 'utf-8')
            this.products = JSON.parse(products)
            return this.products
        }catch(err){
            console.log('File not found.')
        }
    }

    getProductById(id){
        this.#read()
        const productFound = this.products.find(product => product.id === id)
        return productFound ? productFound : console.log('Product ID not found')
    }

    updateProduct(id, modifiedProduct){
        try{
            const products = fs.readFileSync(this.path, 'utf-8')
            this.products = JSON.parse(products)
            //buscamos el producto por id y validamos que la modificación tenga todos los campos
            const validated = this.#validateFields(modifiedProduct)
            const productFound = this.getProductById(id)

            if(validated){
                console.log('ERROR all fields needed')
            }else if(productFound){
                //sobreescribimos el prod manteniendo el id
                const productUpdated = {...modifiedProduct, id: id}
                this.#write()
                console.log('Product modified successfully')
                return productUpdated
            }
            else{
                console.log('Product ID not found')
                return productFound
            }
        }catch(err){
            console.log('File not found')
        }
    }

    deleteProduct(id){
        this.#read()
        const productFound = this.getProductById(id)
        if(productFound){
            //filtramos el array sin el producto y guardamos
            this.products = this.products.filter(product => product.id !== id)
            this.#write()
            console.log('Product deleted successfully')
            return {deletedProduct: productFound}
        }else{
            console.log('Product ID not found')
        }
    }
}

export default {ProductManager}