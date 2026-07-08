import app from "./src/app.js";
import connectDB from "./src/config/data.js";
connectDB();
app.listen(3000,()=>{
    console.log("Server is runing on port 3000")
})