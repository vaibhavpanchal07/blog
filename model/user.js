import mongoose from "mongoose";

const userSchema = mongoose.Schema({
    fullname: String,
    email: String,
    mobile: Number,
    age: Number,
    password: String,
})

const userModel = mongoose.model('user', userSchema);
export default userModel