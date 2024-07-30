const express = require('express');
const cors = require('cors');
require('dotenv').config()
const jwt=require('jsonwebtoken')
const app = express()
var bcrypt = require('bcryptjs');
const port = process.env.PORT || 5000;


const corsOptions={
    origin:['http://localhost:5173'],
    credentials:true,
    optionSuccessStatus:200,
}
app.use(cors(corsOptions))
app.use(express.json())


const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.cxuuz57.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
async function run() {
  try {
    
    const usersCollection = client.db("InstaCash").collection("users");

    // jwt related api
    app.post('/jwt',async(req,res)=>{
        const user=req.body
        const token=jwt.sign(user,process.env.ACCESS_TOKEN_SECRET,{expiresIn:'1h'})
        res.send({token})
    })

    const verifyToken=(req,res,next)=>{
        if(!req.headers.authorization){
            return res.status(401).send({message:'unauthorized access'})
        }
        const token = req.headers.authorization.split(' ')[1];

        jwt.verify(token,process.env.ACCESS_TOKEN_SECRET,(err,decoded)=>{
            if(err){
                return res.status(401).send({ message: 'unauthorized access' })
            }
            req.decoded=decoded
            next()
        })
    }

    //user related api
    app.post('/users',async(req,res)=>{
      const userData=req.body;
      const existingUser = await usersCollection.findOne({
        $or: [{mobile: userData.mobile}, {email: userData.email}]
      })
      if(existingUser){
        return res.send({message: 'user already exists',insertedId: null})
      }

     // Hash the PIN
      const salt = await bcrypt.genSalt(10);
      const hashPin = await bcrypt.hash(userData.pin.toString(), salt);
      
      const user ={
        name: userData.name,
        email: userData.email,
        mobile: userData.mobile,
        pin: hashPin,
        role: userData.role,
        balance: 0,
        status: 'pending'
      }

      const result = await usersCollection.insertOne(user);
      res.send(result)
    })

    app.get('/users',async (req,res)=>{
      const result= await usersCollection.find().toArray()
      res.send(result)
    })

    app.post("/login",async(req,res)=>{
      const {mobile,pin}=req.body;

      const user= await usersCollection.findOne({
        $or: [{mobile}, {email: mobile}]
      });
      if(!user){
        return res.status(404).send({message: 'user not found'})
      }

      const isMatch = await bcrypt.compare(pin.toString(), user.pin);
      if(!isMatch){
        return res.status(401).send({message: 'unauthorized access'});
      }

      const token=jwt.sign(user,process.env.ACCESS_TOKEN_SECRET,{expiresIn:'1h'})
      res.send({token,user})
    })




    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
  }
}
run().catch(console.dir);


app.get('/',(req,res)=>{
    res.send('instaCash is cooking')
})

app.listen(port,()=>{
    console.log(`server is running on port , ${port}`)
})
