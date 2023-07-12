import { Schema, model } from "mongoose"

const MessageSchema = new Schema({
    user: {
        type: String,
        required: true
    },
    message: {
        type: String,
        required: true
    }
})

const Message = model('Message', MessageSchema)
export default Message