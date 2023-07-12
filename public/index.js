const socket = io()
import CartController from '../dao/mongoManagers/cartController.js'
const CM = new CartController()

/* socket.on('products', (data) => {
    render(data)
})

function render(db) {
    const html = db.map((product) => {
        return (`
            <div class="mb-3 w-50">
                <div class="card text-center">
                <h5 class="card-header"> ${product.title} </h5>
                    <div class="card-body"> 
                        <em class="card-title"> ${product.description} </em>
                        <p class="card-text"> <b> $${product.price} </b>  </p>
                        <small>id: ${product._id} </small>
                        
                    </div>
                </div>
            </div>
        `)
    }).join(" ")
    document.getElementById('productsContainer').innerHTML = html
} */

function addToCart(prodId){
    const cartId = req.query.cid

    CM.addToCart(cartId, prodId)
        .then(res => {
            res.send('Product added to cart', {...prodId})
        })
        .catch(err => console.log(err))
}