const express = require('express');
const cors = require('cors');
require('dotenv').config()
const jwt=require('jsonwebtoken')
const app = express()
var bcrypt = require('bcryptjs');
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const corsOptions={
    origin:['http://localhost:5173','https://instacash12.netlify.app'],
    credentials:true,
    optionSuccessStatus:200,
}
app.use(cors(corsOptions))
app.use(express.json())

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
    const transactionsCollection = client.db("InstaCash").collection("transactions");
    const requestCollection = client.db("InstaCash").collection("requestTransaction");

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

    const verifyAgent = async (req,res,next) => {
      const email = req.decoded.email;
      const user = await usersCollection.findOne({email});
      const isAgent = user?.role === 'agent'

      if(!isAgent){
        return res.status(403).send({message:'forbidden access'})
      }
      next();
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
        image_url: userData.image_url,
        balance: 0,
        status: 'pending'
      }

      const result = await usersCollection.insertOne(user);
      res.send(result)
    })

    app.get('/all-users',verifyToken,async (req,res)=>{
      const search=req.query.search;
      let query={
        name:{$regex:search,$options:'i'}
      }

      const result= await usersCollection.find({...query}).toArray()
      res.send(result)
    })

    app.get('/all-user', verifyToken,async(req,res)=>{
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

    app.get("/user/:email", async (req,res)=>{
      const email = req.params.email;
      const result = await usersCollection.findOne({email})
      res.send(result);
    })

    app.patch("/user/block/:id",verifyToken, async(req,res) => {
      const id= req.params.id;
      const filter={_id: new ObjectId(id)};
      const updateDoc = {
        $set:{
          status:'block'
        }
      }
      const result = await usersCollection.updateOne(filter,updateDoc)
      res.send(result)
    })

    app.patch("/user/activate/:id",verifyToken, async(req,res) => {
      const id= req.params.id;
      const {user}=req.body;
      const filter={_id: new ObjectId(id)};
      let updateDoc;
      
       if(user.status==='pending'){
         if(user.role==='agent'){
            updateDoc = {
              $set:{
                status:'activate',
                balance: 10000
              }
            }
         }
         else if(user.role==='user'){
            updateDoc = {
              $set:{
                status:'activate',
                balance: 40
              }
           }
         }
       }
       else{
          updateDoc = {
            $set:{
              status:'activate'
            }
          }
       }

      const result = await usersCollection.updateOne(filter,updateDoc)
      res.send(result)
    })

    //Transactions related api
    app.post("/send-money",verifyToken,async(req,res)=>{
      const transactionData =req.body;

      // Validate Donar
      const validateDonar = await usersCollection.findOne({mobile: transactionData.donar})
      const isMatch = await bcrypt.compare(transactionData.pin.toString(), validateDonar.pin);
      if(!isMatch){
        return res.send({message: 'Your pin is not Correct',insertedId: null});
      }

      // Validate Recipient
      const validateRecipient = await usersCollection.findOne({mobile: transactionData.recipient})
      if(!validateRecipient){
        return res.send({message: 'Recipient not found',insertedId: null})
      }
      if(validateRecipient.role !== 'user'){
        return res.send({message: 'Recipient is not user',insertedId: null})
      }

      // Calculation
      let donarAmount = validateDonar.balance;
      let recipientAmount = validateRecipient.balance;

      recipientAmount = recipientAmount + transactionData.amount;
      if(transactionData.amount >= 100){
        donarAmount = donarAmount  - (transactionData.amount + 5);
      }
      else{
        donarAmount = donarAmount  - transactionData.amount;
      }

      // update and insert data
      await usersCollection.updateOne({mobile: transactionData.donar},{
        $set:{balance: donarAmount}
      })
      await usersCollection.updateOne({mobile: transactionData.recipient},{
        $set:{balance: recipientAmount}
      })
      const result = await transactionsCollection.insertOne(transactionData);
      res.send(result)
    })

    app.post("/cash-in",verifyToken,async(req,res)=>{
      const transactionData = req.body;

      // Validate Recipient
      const validateRecipient = await usersCollection.findOne({mobile: transactionData.recipient});
      const isMatch = await bcrypt.compare(transactionData.pin.toString(), validateRecipient.pin);
      if(!isMatch){
        return res.send({message: 'Your pin is not Correct',insertedId: null});
      }

      // Validate Donar
      const validateDonar = await usersCollection.findOne({mobile: transactionData.donar})
      if(!validateDonar){
        return res.send({message: 'Agent not found',insertedId: null})
      }
      if(validateDonar.role !== 'agent'){
        return res.send({message: 'Donar is not agent',insertedId: null})
      }

      const result = await requestCollection.insertOne(transactionData);
      res.send(result)
    })

    app.post("/cash-out",verifyToken,async(req,res)=>{
      const transactionData =req.body;

      // Validate Donar
      const validateDonar = await usersCollection.findOne({mobile: transactionData.donar})
      const isMatch = await bcrypt.compare(transactionData.pin.toString(), validateDonar.pin);
      if(!isMatch){
        return res.send({message: 'Your pin is not Correct',insertedId: null});
      }

      // Validate Recipient
      const validateRecipient = await usersCollection.findOne({mobile: transactionData.recipient})
      if(!validateRecipient){
        return res.send({message: 'Recipient not found',insertedId: null})
      }
      if(validateRecipient.role !== 'agent'){
        return res.send({message: 'Recipient is not agent',insertedId: null})
      }

      const result = await requestCollection.insertOne(transactionData);
      res.send(result)
    })

    app.get("/my-transactions/:mobile",verifyToken,async(req,res)=>{
      const mobile=req.params.mobile;
      const result = await transactionsCollection.find({$or: [
        { donar: mobile },
        { recipient: mobile }
      ]}).toArray();
      res.send(result)
    });
    
    app.get("/all-transactions",verifyToken,async(req,res)=>{
      const result = await transactionsCollection.find().toArray();
      res.send(result)
    });

    //Request related api
    app.get("/transactions-req/:mobile",verifyToken,async(req,res)=>{
      const mobile=req.params.mobile;
      const result = await requestCollection.find({$or: [
        { donar: mobile },
        { recipient: mobile }
      ]}).toArray();
      res.send(result)
    })

    app.delete("/transaction-req/:id",verifyToken,async(req,res)=>{
      const id=req.params.id;
      const filter = {_id: new ObjectId(id)};
      const result = await requestCollection.deleteOne(filter);
      res.send(result);
    })

    app.post("/accept-req/:id",verifyToken,verifyAgent,async(req,res)=>{
      const id=req.params.id;
      const filter = {_id: new ObjectId(id)};
      const reqData= await requestCollection.findOne(filter);
      const Donar = await usersCollection.findOne({mobile: reqData.donar});
      const Recipient = await usersCollection.findOne({mobile: reqData.recipient});
      let reqProcess, donarAmount, recipientAmount;

      if(reqData.process==='Cash In Request'){
        reqProcess='Cash In';
        donarAmount = Donar.balance - reqData.amount
        recipientAmount = Recipient.balance + reqData.amount
      }
      else if(reqData.process==='Cash Out Request'){
        reqProcess='Cash Out';
        donarAmount = Donar.balance - (reqData.amount + reqData.amount*0.015)
        recipientAmount = Recipient.balance + (reqData.amount + reqData.amount*0.015)
      }

      const transactionData ={
        donar: reqData.donar,
        recipient: reqData.recipient,
        amount: reqData.amount,
        pin: reqData.pin,
        date: new Date().toLocaleDateString(),
        process: reqProcess
      }

      await usersCollection.updateOne({mobile: reqData.donar},{
        $set:{balance: donarAmount}
      })

      await usersCollection.updateOne({mobile: reqData.recipient},{
        $set:{balance: recipientAmount}
      })

      await requestCollection.deleteOne(filter);
      const result= await transactionsCollection.insertOne(transactionData);
      res.send(result)
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
