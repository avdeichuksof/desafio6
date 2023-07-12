import { Router } from 'express'
const router = new Router()
import ProductController from '../dao/mongoManagers/productController.js'
const productManager = new ProductController()
import Product from '../dao/models/productModel.js'


router.get('/', async(req, res) => {
    const {query, limit, page} = req.query
    try{
        const data = await productManager.getProducts(query, limit, page)

        return res.status(200).json({
            status: 'success',
            payload: data.docs,
            totalPages: data.totalPages,
            prevPage: data.prevPage,
            nextPage: data.nextPage,
            page: data.page,
            hasPrevPage: data.hasPrevPage,
            hasNextPage: data.hasNextPage,
            prevLink: data.hasPrevPage ? `http://localhost:8080/api/products/?page=${data.prevPage}` : null,
            nextLink: data.hasNextPage ? `http://localhost:8080/api/products/?page=${data.nextPage}` : null,
        })
    }catch(err){
        console.log(err)
    }
})

router.get('/:id', (req, res) => {
    const id = req.params.id
    const product = productManager.getProductById(id)

    if(product) return res.status(200).send({data: product})
    return res.status(204).send({message: 'Product not found'})
})

router.post('/', (req, res) => {
    const newProd = req.body
    const product = new Product(newProd)
    productManager.addProduct(product)
        .then(product => {
            res.status(201).send({message: "Product created successfully", data: product})
        })
        .catch(err => res.status(500).send({err}))
})

router.put('/:id', (req, res) => {
    const id = req.params.id
    const newData = req.body
    productManager.updateProduct(id, newData)
        .then(product => {
            res.status(201).send({message: 'Product updated successfully', data: product})
        })
        .catch(err => res.status(500).send({err}))
})

router.delete('/:id', (req, res) => {
    const id = req.params.id
    const product = productManager.deleteProduct(id)
    if(product) return res.status(200).send({message: 'Product deleted successfully', data: product})
    return res.status(204).send({message: 'Error deleting product'})
})

export default router