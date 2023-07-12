import mongoose from "mongoose"
const URL = 'mongodb+srv://savdeichuk:KCQc4E3Hn13lmNdx@ecommerce.yjjbpjj.mongodb.net/ecommerce'

export default {
    URL,
    connect: () => {
        return mongoose.connect(URL, {useUnifiedTopology: true, useNewUrlParser: true})
        .then((connect) => {
            console.log('Connected to DB')
        })
        .catch((err) => console.log(err))
    }
}