import mongoose from 'mongoose'

const dbconn = async ()=>{
    try {
        const connectionInstance = await mongoose.connect(process.env.DB_URL);
        console.log(connectionInstance.connection.host);
        
    } catch (error) {
        console.log("DB ERROR");
        
    }
}

export default dbconn;