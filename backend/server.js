
require('dotenv').config({ path: './.env' });

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const nodemailer = require('nodemailer');




//  Models 
const User = require("./models/User");
const StudyMaterial = require("./models/StudyMaterial.js");
const SavedNote = require("./models/SaveNotes.js");
const Payment = require("./models/Payment.js"); 

// Routes
const cloudinaryUploadRoutes = require("./routes/cloudinaryUpload");
const directCloudinaryUploadRoutes = require("./routes/directCloudinaryUpload");
const paymentRoutes = require("./routes/paymentRoutes");


 
const connectdb = require("./db");

const app = express();

// ✅ Increase payload limit
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));


app.use(cookieParser());
app.use(express.json());
// app.use(cors());
app.use(cors({
  origin: function (origin, callback) {
    console.log('CORS request from origin:', origin);
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Allow localhost for development
    if (origin.includes('localhost')) return callback(null, true);
    
    // Allow any vercel.app subdomain
    if (origin.includes('.vercel.app')) return callback(null, true);
    
    // Allow specific frontend URL from env
    if (origin === process.env.FRONTEND_URL) return callback(null, true);
    
    console.log('CORS blocked origin:', origin);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));




// Connect to DB
connectdb();

const PORT = process.env.PORT || 7000;

console.log("PORT:", PORT);

console.log("MONGO_URI:", process.env.MONGO_URI);



// Root route
app.get("/", (req, res) => {
  res.send("Hello, server is running!");
});

// Signup Route
app.post("/api/Signup", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    console.log("Request body:", req.body);

    // 1. Validate
    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // 2. Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // 3. Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    console.log("Password hashed:", hashedPassword);

    // 4. Create new user
    const newUser = new User({ name, email, password: hashedPassword, role });
    await newUser.save();
    console.log("New user saved:", newUser);

    // 5. Generate JWT Token
    console.log("Generating token...");
    const token = jwt.sign(
      { email: newUser.email, id: newUser._id, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    // res.cookie("token",token);
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // use true only with HTTPS
      sameSite: "lax", // or "none" if using HTTPS
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    console.log("Token:", token);

  
 
  res.status(201).json({
  user: {
    id: newUser._id,
    name: newUser.name,
    email: newUser.email,
    role: newUser.role
  },
  token
});
  }
   catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: "Something went wrong", error: error.message });
  }



});


// Login Route
app.post("/api/Login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validate fields
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    // 2. Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // 3. Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // 4. Generate JWT token
    const token = jwt.sign(
      { email: user.email, id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // 5. Set token in cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    
    res.status(200).json({
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role, // this is important
      },
      token
    });


  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Something went wrong", error: error.message });
  }
});


// Log out Route
app.get("/api/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: false, // same as you set during login
    sameSite: "lax",
  });
  res.status(200).json({ message: "Logged out successfully" });
});

// Update user profile
app.put("/api/user/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, role } = req.body;

    // Validate input
    if (!name || !email || !role) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if email is already taken by another user
    const existingUser = await User.findOne({ email, _id: { $ne: id } });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Update user
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { name, email, role },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      message: "Profile updated successfully",
      user: {
        id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role
      }
    });
  } catch (error) {
    console.error("Profile update failed:", error);
    res.status(500).json({ message: "Profile update failed" });
  }
});

// Delete user account
app.delete("/api/user/:id", async (req, res) => {
  try {
    const { id } = req.params;
    
    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "Account deleted successfully" });
  } catch (error) {
    console.error("Account deletion failed:", error);
    res.status(500).json({ message: "Account deletion failed" });
  }
});






// Use Cloudinary upload routes
app.use("/api/upload", directCloudinaryUploadRoutes);
app.use("/api/cloudinary-upload", cloudinaryUploadRoutes);
app.use("/api/direct-upload", directCloudinaryUploadRoutes);


// GET /api/seller/notes - Get user-specific materials
app.get("/seller/notes", async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    
    const notes = await StudyMaterial.find({ uploadedBy: email });
    res.json(notes);
  } catch (err) {
    console.error("Failed to fetch notes:", err);
    res.status(500).json({ message: "Failed to fetch notes" });
  }
});

// DELETE /seller/notes/:id - Delete a specific note
app.delete("/seller/notes/:id", async (req, res) => {
  try {
    const { id } = req.params;
    
    // Find the note first to get the file info
    const note = await StudyMaterial.findById(id);
    if (!note) {
      return res.status(404).json({ message: "Note not found" });
    }
    
    // Delete from Cloudinary
    if (note.pdf && note.pdf.public_id) {
      const cloudinary = require('cloudinary').v2;
      try {
        await cloudinary.uploader.destroy(note.pdf.public_id, { resource_type: 'raw' });
      } catch (cloudinaryError) {
        console.error('Cloudinary deletion error:', cloudinaryError);
      }
    }
    
    // Delete from database
    await StudyMaterial.findByIdAndDelete(id);
    
    res.json({ message: "Note deleted successfully" });
  } catch (err) {
    console.error("Failed to delete note:", err);
    res.status(500).json({ message: "Failed to delete note" });
  }
});



// Middleware to check if user is buyer
const checkBuyerRole = async (req, res, next) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    if (user.role !== 'buyer') {
      return res.status(403).json({ message: "Only buyers can access this feature" });
    }
    
    next();
  } catch (error) {
    res.status(500).json({ message: "Authorization failed", error: error.message });
  }
};

app.post("/api/save-note", checkBuyerRole, async (req, res) => {
  try {
    const { userId, title, description, category, price, fileName, previewUrl } = req.body;

    // Prevent duplicates
    const existing = await SavedNote.findOne({ userId, title });
    if (existing) {
      return res.status(409).json({ message: "Note already saved" });
    }

    const newNote = new SavedNote({ userId, title, description, category, price, fileName, previewUrl });
    await newNote.save();

    res.status(201).json({ message: "Note saved" });
  } catch (error) {
    res.status(500).json({ message: "Save failed", error: error.message });
  }
});




app.get("/api/saved-notes/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    if (user.role !== 'buyer') {
      return res.status(403).json({ message: "Only buyers can access saved notes" });
    }
    
    const notes = await SavedNote.find({ userId: req.params.userId });
    res.status(200).json(notes);
  } catch (err) {
    res.status(500).json({ message: "Error fetching saved notes", error: err.message });
  }
});



app.delete("/api/saved-notes/:id", async (req, res) => {
  try {
    const note = await SavedNote.findById(req.params.id);
    if (!note) {
      return res.status(404).json({ message: "Note not found" });
    }
    
    const user = await User.findById(note.userId);
    if (user.role !== 'buyer') {
      return res.status(403).json({ message: "Only buyers can unsave notes" });
    }
    
    await SavedNote.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: "Note unsaved successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to unsave note" });
  }
});


app.get("/api/materials/count", async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const count = await StudyMaterial.countDocuments({ uploadedBy: email });
    res.json({ count });
  } catch (error) {
    console.error("Error fetching material count:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// Category management routes
app.get("/api/seller/categories", async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    res.json({ categories: user.categories });
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({ message: "Failed to fetch categories" });
  }
});

app.post("/api/seller/categories", async (req, res) => {
  try {
    const { email, categories } = req.body;
    
    if (!email || !categories || !Array.isArray(categories)) {
      return res.status(400).json({ message: "Email and categories array are required" });
    }
    
    const user = await User.findOneAndUpdate(
      { email },
      { categories },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    res.json({ message: "Categories updated successfully", categories: user.categories });
  } catch (error) {
    console.error("Error updating categories:", error);
    res.status(500).json({ message: "Failed to update categories" });
  }
});

// Payment routes
app.use("/api/payment", paymentRoutes);


// get all study material for buyer
app.get('/api/all-materials', async (req, res) => {
  try {
    // Replace 'StudyMaterial' with your actual model name
    const materials = await StudyMaterial.find({});
    res.json(materials);
  } catch (error) {
    console.error('Error fetching all materials:', error);
    res.status(500).json({ error: 'Failed to fetch materials' });
  }
});

// PDF Preview endpoint - Cloudinary only
app.get('/api/preview-pdf/:materialId', async (req, res) => {
  try {
    const { materialId } = req.params;
    const { userEmail } = req.query;
    
    // Find the material
    const material = await StudyMaterial.findById(materialId);
    if (!material) {
      return res.status(404).json({ error: 'Material not found' });
    }
    
    // Check if user has purchased this material
    let hasPurchased = false;
    if (userEmail) {
      const purchase = await Payment.findOne({ 
        buyerEmail: userEmail, 
        itemTitle: material.title,
        status: 'completed' 
      });
      hasPurchased = !!purchase;
    }
    
    const pdfUrl = material.pdf?.fullUrl;
    if (!pdfUrl) {
      return res.status(404).json({ error: 'PDF file not found' });
    }
    
    // Add headers for frontend modal trigger
    res.setHeader('X-Preview-Mode', hasPurchased ? 'false' : 'true');
    res.setHeader('X-Material-Title', material.title);
    res.setHeader('X-Material-Price', material.price.toString());
    res.setHeader('X-Material-Category', material.category);
    
    // Redirect to Cloudinary URL
    return res.redirect(pdfUrl);
    
  } catch (error) {
    console.error('PDF preview error:', error);
    res.status(500).json({ error: 'Failed to serve PDF preview' });
  }
});

// Check if user has purchased this material endpoint
app.get('/api/check-purchase/:materialId', async (req, res) => {
  try {
    const { materialId } = req.params;
    const { userEmail } = req.query;
    
    if (!userEmail) {
      return res.json({ hasPurchased: false });
    }
    
    const material = await StudyMaterial.findById(materialId);
    if (!material) {
      return res.status(404).json({ error: 'Material not found' });
    }
    
    const purchase = await Payment.findOne({ 
      buyerEmail: userEmail, 
      itemTitle: material.title,
      status: 'completed' 
    });
    
    res.json({ 
      hasPurchased: !!purchase,
      totalPages: material.totalPages || 0,
      previewPages: 4
    });
  } catch (error) {
    console.error('Purchase check error:', error);
    res.status(500).json({ error: 'Failed to check purchase status' });
  }
});

// Restricted PDF viewer endpoint
app.get('/api/restricted-pdf/:materialId', async (req, res) => {
  try {
    const { materialId } = req.params;
    const { userEmail } = req.query;
    
    // Try to find by ID first
    let material = await StudyMaterial.findById(materialId);
    
    // If not found by ID, try to find by title (for saved notes)
    if (!material) {
      const savedNote = await SavedNote.findById(materialId);
      if (savedNote) {
        material = await StudyMaterial.findOne({ title: savedNote.title });
      }
    }
    
    if (!material) {
      return res.status(404).json({ error: 'Material not found' });
    }
    
    let hasPurchased = false;
    if (userEmail) {
      const purchase = await Payment.findOne({ 
        buyerEmail: userEmail, 
        itemTitle: material.title,
        status: 'completed' 
      });
      hasPurchased = !!purchase;
    }
    
    const pdfUrl = material.pdf?.fullUrl;
    if (!pdfUrl) {
      return res.status(404).json({ error: 'PDF not found' });
    }
    
    // For purchased items, return full PDF URL
    if (hasPurchased) {
      return res.json({ 
        pdfUrl,
        isPurchased: true,
        previewOnly: false
      });
    }
    
    // For non-purchased items, return limited preview URL
    // Google Docs viewer with page range parameter (pages 1-3)
    const previewUrl = `${pdfUrl}#page=1&view=FitH&toolbar=0&navpanes=0&scrollbar=0`;
    
    return res.json({ 
      pdfUrl: previewUrl,
      isPurchased: false,
      previewOnly: true,
      previewPages: 3,
      material: {
        title: material.title,
        price: material.price,
        category: material.category,
        id: material._id
      }
    });
  } catch (error) {
    console.error('Restricted PDF error:', error);
    res.status(500).json({ error: 'Failed to load PDF' });
  }
});

// Buyer payment endpoint
app.get('/api/buyer/payments', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const user = await User.findOne({ email });
    if (!user || user.role !== 'buyer') {
      return res.status(403).json({ error: 'Only buyers can access payment history' });
    }
    
    const payments = await Payment.find({ buyerEmail: email })
      .sort({ createdAt: -1, date: -1 });
    
    const totalSpent = payments.reduce((sum, payment) => sum + (payment.amount || 0), 0);
    
    const formattedPayments = payments.map(payment => ({
      itemTitle: payment.itemTitle,
      sellerEmail: payment.sellerEmail,
      amount: payment.amount,
      paymentId: payment.paymentId,
      status: payment.status,
      date: payment.date
    }));
    
    res.json({
      payments: formattedPayments,
      totalSpent
    });
  } catch (error) {
    console.error('Buyer payment fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch payment data' });
  }
});

// Download purchased PDF endpoint - Cloudinary only
app.get('/api/download-pdf/:materialId', async (req, res) => {
  try {
    const { materialId } = req.params;
    const { userEmail } = req.query;
    
    if (!userEmail) {
      return res.status(401).json({ error: 'User email required' });
    }
    
    // Find the material
    const material = await StudyMaterial.findById(materialId);
    if (!material) {
      return res.status(404).json({ error: 'Material not found' });
    }
    
    // Check if user has purchased this material
    const purchase = await Payment.findOne({ 
      buyerEmail: userEmail, 
      itemTitle: material.title,
      status: 'completed' 
    });
    
    if (!purchase) {
      return res.status(403).json({ error: 'Purchase required to download' });
    }
    
    // Get the Cloudinary PDF URL
    const pdfUrl = material.pdf?.fullUrl;
    if (!pdfUrl) {
      return res.status(404).json({ error: 'PDF file not found in database' });
    }
    
    // Redirect to Cloudinary URL with download flag
    const downloadUrl = pdfUrl.replace('/upload/', '/upload/fl_attachment/');
    return res.redirect(downloadUrl);
    
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Failed to download PDF' });
  }
});

// Buyer purchased items endpoint
app.get('/api/buyer/purchased', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const user = await User.findOne({ email });
    if (!user || user.role !== 'buyer') {
      return res.status(403).json({ error: 'Only buyers can access purchased items' });
    }
    
    // Get all payments by this buyer
    const payments = await Payment.find({ 
      buyerEmail: email, 
      status: 'completed' 
    });
    
    // Get the item titles from payments
    const itemTitles = payments.map(payment => payment.itemTitle);
    
    // Find study materials that match these titles
    const purchasedItems = await StudyMaterial.find({ 
      title: { $in: itemTitles } 
    });
    
    // Add purchase info to each item
    const itemsWithPurchaseInfo = purchasedItems.map(item => {
      const payment = payments.find(p => p.itemTitle === item.title);
      return {
        ...item.toObject(),
        purchaseDate: payment?.date,
        purchasePrice: payment?.amount
      };
    });
    
    res.json(itemsWithPurchaseInfo);
  } catch (error) {
    console.error('Purchased items fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch purchased items' });
  }
});

//payment endpoint 
app.get('/api/seller/payments', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    console.log('\n=== FETCHING PAYMENTS FOR SELLER ===');
    console.log('Seller email:', email);
    
    // Directly find payments by sellerEmail field
    const payments = await Payment.find({ sellerEmail: email })
      .sort({ createdAt: -1, date: -1 });
    
    console.log('Found payments with sellerEmail:', payments.length);
    
    // Format payments for display
    const formattedPayments = payments.map(payment => {
      const plainPayment = payment.toObject ? payment.toObject() : payment;
      
      console.log('Processing payment:', {
        id: plainPayment._id,
        itemTitle: plainPayment.itemTitle,
        amount: plainPayment.amount,
        buyerName: plainPayment.buyerName
      });
      
      return {
        itemTitle: plainPayment.itemTitle || 'Unknown Item',
        buyerName: plainPayment.buyerName || plainPayment.user?.name || 'Unknown Buyer',
        buyerEmail: plainPayment.buyerEmail || plainPayment.user?.email || 'Unknown Email',
        date: plainPayment.date || plainPayment.createdAt || new Date(),
        paymentId: plainPayment.paymentId || plainPayment.razorpay_payment_id || plainPayment._id,
        amount: plainPayment.amount || plainPayment.amountPaid || 0,
        status: plainPayment.status || 'completed'
      };
    });
    
    console.log('\n=== FINAL RESULTS ===');
    console.log('Seller:', email);
    console.log('Total payments found:', formattedPayments.length);
    
    // Calculate earnings
    const total = formattedPayments.reduce((sum, p) => sum + (p.amount || 0), 0);
    const thisMonth = formattedPayments
      .filter(p => {
        const paymentDate = new Date(p.date);
        const currentDate = new Date();
        return paymentDate.getMonth() === currentDate.getMonth() && 
               paymentDate.getFullYear() === currentDate.getFullYear();
      })
      .reduce((sum, p) => sum + (p.amount || 0), 0);
    const pending = formattedPayments
      .filter(p => p.status === 'pending')
      .reduce((sum, p) => sum + (p.amount || 0), 0);
    
    console.log('Total earnings: ₹' + total);
    console.log('This month: ₹' + thisMonth);
    console.log('Pending: ₹' + pending);
    
    res.json({
      payments: formattedPayments,
      earnings: { total, thisMonth, pending }
    });
  } catch (error) {
    console.error('Payment fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch payment data' });
  }
});

// Contact email route
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    
    const transporter = nodemailer.createTransporter({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      auth: {
        user: 'contactedulinker@gmail.com',
        pass: 'your_gmail_password_here'
      },
      tls: {
        rejectUnauthorized: false
      }
    });
    
    await transporter.sendMail({
      from: email,
      to: 'contactedulinker@gmail.com',
      subject: `Contact from ${name}`,
      html: `<p><strong>Name:</strong> ${name}</p><p><strong>Email:</strong> ${email}</p><p><strong>Message:</strong> ${message}</p>`
    });
    
    res.json({ message: 'Email sent successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to send email' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});

