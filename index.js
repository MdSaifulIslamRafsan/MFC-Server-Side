const express = require('express')
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require("dotenv").config()
const app = express()
const port = process.env.PORT || 5000
const corsOption = {
    origin : ['http://localhost:5173', 'http://localhost:5174'],
    credentials: true,
    optionSuccessStatus: 200

}


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_NAME}:${process.env.DB_PASS}@cluster0.edk1eij.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
app.use(cors(corsOption));
app.use(express.json())
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)

    const usersCollection = client.db('MFS-SCIC-Task').collection('users')

    app.post('/api/register', async (req, res) => {
      try {
        const { name, pin, mobile, email } = req.body;
        const hashedPin = await bcrypt.hash(pin, 10); 
        const existingUser = await usersCollection.findOne({ $or: [{ mobile }, { email }] });

        if (existingUser) {
          return res.status(409).json({ message: 'User already exists' });
        }
        const result = await usersCollection.insertOne({
          name,
          hashedPin,
          mobile,
          email,
          status: 'pending' 
        });
    
    
        res.status(200).json({ message: 'User registered, waiting for admin approval', userId: result.insertedId });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
  
    });

    app.post('/api/login', async (req, res) => {
      const { identifier, pin } = req.body;
      const user = await usersCollection.findOne({ $or: [{ mobile: identifier }, { email: identifier }] });

      if (!user) {
          return res.status(400).json({ message: 'Invalid credentials' });
      }

      const isPinValid = await bcrypt.compare(pin, user.hashedPin);
      if (!isPinValid) {
          return res.status(400).json({ message: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '90d' });
      res.json({ token });
  });

  // Middleware to verify JWT token
  const authenticateToken = (req, res, next) => {
      const token = req.header('Authorization')?.split(' ')[1];
      if (!token) {
          return res.status(401).json({ message: 'Access denied' });
      }

      try {
          const verified = jwt.verify(token, process.env.JWT_SECRET);
          req.user = verified;
          next();
      } catch (err) {
          res.status(400).json({ message: 'Invalid token' });
      }
  };

  // Route to get current user info
  app.get('/api/current-user', authenticateToken, async (req, res) => {
      try {
          const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) }, { projection: { hashedPin: 0 } });
          if (!user) {
              return res.status(404).json({ message: 'User not found' });
          }
          res.json(user);
      } catch (err) {
          console.error('Fetch user error:', err);
          res.status(500).json({ message: 'Server error' });
      }
  });


    // await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);




app.get('/', (req, res) => {
  res.send('MFC server side running!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})