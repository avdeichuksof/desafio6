import Product from '../models/productModel.js'

class ProductController{
    constructor(path){
        this.path = path
    }

    getProducts = async (query, limit, page) => {
        try{
            const filter = query ? {category: query} : {} 
            const options = {
                limit: limit || 4,
                page: page || 1
            }
            const products = await Product.paginate(filter, options)
            return products
        }catch(err){
            console.log(err)
        }
    }
    
    getProductById(id) {
        try{
            const productFound = Product.findOne({_id: id}).lean
            return productFound
        }catch(err){
            console.log(err, {message: 'Product not found'})
        }
    }
    
    addProduct(newProd) {
        try{
            let product = new Product(newProd)
            return product.save()
        }catch(err){
            console.log(err)
        }
    }
    
    updateProduct(id, newData) {
        const updateProduct = this.getProductById(id)
        if(updateProduct){
            return updateProduct.updateOne({_id: id}, {$set: newData})
        }else{
            console.log('Error updating product')
        }
    }
    
    deleteProduct = async (id) => {
        try{
            const deletedProd = await Product.deleteOne({_id: id})
            deletedProd ? console.log('Product deleted successfully') 
                        : console.log('Product not found')
        }catch(err){
            console.log(err)
        }
    }
}


export default ProductController