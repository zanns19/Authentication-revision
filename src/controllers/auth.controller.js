import mongoose from "mongoose";
import userModel from "../models/user.model.js"
import config from "../config/config.js";
import crypto from "crypto"
import jwt from "jsonwebtoken"
export async function register(req,res) {
    
    const { username, email, password } = req.body;

    const isAlreadyRegistered = await userModel.findOne({
        $or: [
            { username },
            { email }
        ]
    })

    if (isAlreadyRegistered) {
        res.status(409).json({
            message: "Username or email already exists"
        })
    }
    const hashedPassword= crypto.createHash("sha256").update(password).digest("hex");
    const user = await userModel.create({
        username,
        email,
        password:hashedPassword
    })
    const token = jwt.sign({id:user._id},config.JWT_SECRET,{
        expiresIn:"1d"
    })
    res.status(201).json({message:"user Register Successfully!" ,
        user:{
            username:user.username,
            email:user.email
        },
        token
    })
}