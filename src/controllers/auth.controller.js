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
    const accessToken = jwt.sign({id:user._id},config.JWT_SECRET,{
        expiresIn:"15m"
    })
    const refreshToken =   jwt.sign({id:user._id},config.JWT_SECRET,{
        expiresIn:"7d"
    })
    res.cookie("refreshToken",refreshToken,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:7*24*60*60*1000
    })
    res.status(201).json({message:"user Register Successfully!" ,
        user:{
            username:user.username,
            email:user.email
        },
        accessToken
    })
}
export async function GetMe(req,res) {
    const token = req.headers.authorization?.split(" ")[1];
    if(!token){
        return res.status(401).json({
            message:"Token not Found!"
        })
    }
    const decoded = jwt.verify(token,config.JWT_SECRET)
    if(!decoded){
        return res.status(401).json({
            message:"Token is not Valid!"
        })
    }
const user = await userModel.findById(decoded.id)
    res.status(200).json({
            message:"User Fetch Successfully!",
            user:{
                username:user.username,
                email:user.email,
            }
            
        })
    
}
export async function refreshToken(req,res) {
    const refreshToken = req.cookies.refreshToken
    const decoded = jwt.verify(refreshToken,config.JWT_SECRET)
    if(!decoded){
        return res.status(401).json({
            message:"Token is not Valid!"
        })
    }
    const accessToken = jwt.sign({id:decoded.id},config.JWT_SECRET,{expiresIn:"15m"})
    res.status(200).json({
            message:"Access Token generated Successfully!",
            accessToken
        })
    const newRefreshToken=jwt.sign({id:decoded.id},config.JWT_SECRET,{expiresIn:"7d"})
    res.cookie("refreshToken",newRefreshToken,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:7*24*60*60*1000
    })
}