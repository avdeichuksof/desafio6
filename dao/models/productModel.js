import { Schema, model } from "mongoose"
import paginate from "mongoose-paginate-v2"

const ProductSchema = new Schema({
    title: {
        type: String,
        required: true,
        unique: true
    },
    description: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    thumbnail: {
        type: String,
        required: true
    },
    code: {
        type: String,
        required: true,
        unique: true
    },
    stock: {
        type: Number,
        required: true
    },
    status: {
        type: Boolean,
        default: true,
        required: true
    },
    category: {
        type: String,
        required: true,
        enum: ['artist', 'cinema', 'classic', 'flowers', 'geometric', 'hobbies', 'oneline', 'realista', 'varios']
    }
})

ProductSchema.plugin(paginate)

const Product = model('Product', ProductSchema)
export default Product