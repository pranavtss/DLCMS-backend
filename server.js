const express = require("express")
require("dotenv").config()
const cors = require("cors")
const helmet = require("helmet")
const morgan = require("morgan")
const jwt = require("jsonwebtoken")
const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const crypto = require("crypto")
const path = require("path")
const fs = require("fs")
const multer = require("multer")
const { OAuth2Client } = require("google-auth-library")
const User = require("./models/User")
const Course = require("./models/Course")
const Review = require("./models/Review")
const Enrollment = require("./models/Enrollment")

const app = express()

app.use(helmet({
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}))
app.use(morgan("combined"))
app.use(cors())
app.use(express.json())
const uploadsDir = path.join(__dirname, "uploads")
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true })
  console.log("✓ Uploads directory created at:", uploadsDir)
} else {
  console.log("✓ Uploads directory exists at:", uploadsDir)
}

app.use("/uploads", express.static(uploadsDir))

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, uploadsDir)
    },
    filename: (req, file, cb) => {
      const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_")
      // Use a stable name so re-uploading the same file does not create duplicates
      const filename = safeName
      console.log("✓ Saving file (overwriting if exists):", filename)
      cb(null, filename)
    },
  }),
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB for educational materials
})

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/dlcms"
const ADMIN_EMAIL = "admin@dlcms"
const ADMIN_PASSWORD = "admin"
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || ""
const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production"
const JWT_EXPIRE = process.env.JWT_EXPIRE || "7d"
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null

// JWT Token Generation
const generateToken = (userId, email, role) => {
  return jwt.sign(
    { userId, email, role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRE }
  )
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1] // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ message: "Access token required" })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error("❌ Token verification failed:", err.message)
      return res.status(403).json({ message: "Invalid or expired token" })
    }
    req.user = user
    next()
  })
}

// Admin Authorization Middleware
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== "Admin") {
    console.error(`❌ Unauthorized access attempt by non-admin: ${req.user.email}`)
    return res.status(403).json({ message: "Admin access required" })
  }
  next()
}

const ensureAdminAccount = async () => {
  try {
    const adminHash = await bcrypt.hash(ADMIN_PASSWORD, 10)
    const existing = await User.findOne({ email: ADMIN_EMAIL })

    if (!existing) {
      const newAdmin = await User.create({
        name: "Admin",
        email: ADMIN_EMAIL,
        password: adminHash,
        role: "Admin",
      })
      console.log("✓ Admin account created with ID:", newAdmin._id.toString())
      return
    }

    console.log("✓ Admin account exists, email:", existing.email, "role:", existing.role)
    
    const passwordMatches = await bcrypt.compare(ADMIN_PASSWORD, existing.password)
    if (existing.role !== "Admin" || !passwordMatches) {
      existing.role = "Admin"
      existing.password = adminHash
      await existing.save()
      console.log("✓ Admin account updated")
    } else {
      console.log("✓ Admin account verified and up to date")
    }
  } catch (error) {
    console.error("✗ Admin account check failed:", error.message)
  }
}

mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log("MongoDB connected")
    await ensureAdminAccount()
  })
  .catch((error) => console.error("MongoDB connection error:", error.message))

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" })
})

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body
  console.log(`\n📧 Login attempt: ${email}`)
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required." })
  }
  console.log(`🔍 Looking up user: ${email.toLowerCase()}`)
  User.findOne({ email: email.toLowerCase() })
    .then(async (user) => {
      if (!user) {
        console.log(`❌ Login failed: User not found for email ${email.toLowerCase()}`)
        return res.status(401).json({ message: "Invalid credentials." })
      }
      console.log(`✓ User found: ${user.name} (role: ${user.role})`)
      if (email.toLowerCase() === "admin@dlcms" && user.role !== "Admin") {
        console.log(`❌ Login failed: Admin email used but user role is ${user.role}`)
        return res.status(403).json({ message: "Unauthorized admin login." })
      }
      if (user.role === "Admin" && user.email !== "admin@dlcms") {
        console.log(`❌ Login failed: User has Admin role but email is ${user.email}`)
        return res.status(403).json({ message: "Unauthorized admin login." })
      }
      const match = await bcrypt.compare(password, user.password)
      console.log(`🔐 Password comparison result: ${match}`)
      if (!match) {
        console.log(`❌ Login failed: Password mismatch for ${email.toLowerCase()}`)
        return res.status(401).json({ message: "Invalid credentials." })
      }
      console.log(`✅ Login successful for ${email.toLowerCase()}`)
      const token = generateToken(user._id, user.email, user.role)
      return res.json({ 
        message: "Login successful", 
        userId: user._id, 
        role: user.role, 
        name: user.name,
        token: token 
      })
    })
    .catch((error) => {
      console.error("❌ Login error:", error.message)
      res.status(500).json({ message: "Login failed.", error: error.message })
    })
})

app.post("/api/auth/register", async (req, res) => {
  console.log("\n🎯 ==== REGISTRATION REQUEST RECEIVED ====")
  console.log("Body:", req.body)
  try {
    const { name, email, password, role, adminSecret } = req.body
    console.log('\n📝 Registration attempt:')
    console.log('  Name:', name)
    console.log('  Email:', email)
    console.log('  Role:', role)
    
    if (!name || !email || !password) {
      console.log('❌ Validation failed: Missing fields')
      return res.status(400).json({ message: "Name, email, and password required." })
    }

    if (name.trim().toLowerCase() === "admin") {
      return res.status(403).json({ message: "Username 'admin' is reserved." })
    }

    if (email.trim().toLowerCase() === "admin@dlcms") {
      return res.status(403).json({ message: "Admin account is reserved." })
    }
    
    if (role === "Admin") {
      const ADMIN_SECRET = process.env.ADMIN_SECRET || "dlcms-admin-2026"
      if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ message: "Unauthorized admin creation." })
      }
    }
    
    const existing = await User.findOne({ email: email.toLowerCase() })
    if (existing) {
      console.log('❌ Registration failed: Account already exists')
      return res.status(409).json({ message: "Account already exists." })
    }
    
    const hashed = await bcrypt.hash(password, 10)
    console.log('✓ Password hashed')
    
    const userDoc = {
      name,
      email: email.toLowerCase(),
      password: hashed,
      role: role === "Admin" ? "Admin" : "Learner",
    }
    console.log('📝 Creating user with data:', { ...userDoc, password: '***' })
    
    const user = await User.create(userDoc)
    
    console.log('✅ User created successfully:', user._id)
    return res.status(201).json({ message: "Account created", userId: user._id, role: user.role, name: user.name })
  } catch (error) {
    console.error('❌ Registration error:', error.message)
    console.error('❌ Error name:', error.name)
    console.error('❌ Full error:', error)
    if (error.errors) {
      console.error('❌ Validation errors:', error.errors)
    }
    return res.status(500).json({ message: "Registration failed.", error: error.message })
  }
})

app.post("/api/auth/google", async (req, res) => {
  try {
    const { credential } = req.body

    if (!credential) {
      return res.status(400).json({ message: "Google credential is required." })
    }

    if (!googleClient) {
      return res.status(500).json({
        message: "Google sign-in is not configured on server. Add GOOGLE_CLIENT_ID in backend environment.",
      })
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    })
    const payload = ticket.getPayload()

    if (!payload || !payload.email_verified || !payload.email) {
      return res.status(401).json({ message: "Invalid Google account." })
    }

    const email = payload.email.toLowerCase()
    const name = payload.name || email.split("@")[0]

    if (email === ADMIN_EMAIL) {
      return res.status(403).json({ message: "Google login is not allowed for admin account." })
    }

    let user = await User.findOne({ email })

    if (!user) {
      const tempPassword = crypto.randomBytes(24).toString("hex")
      const hashed = await bcrypt.hash(tempPassword, 10)
      user = await User.create({
        name,
        email,
        password: hashed,
        role: "Learner",
      })
    }

    if (user.role === "Admin") {
      return res.status(403).json({ message: "Unauthorized admin login." })
    }

    const token = generateToken(user._id, user.email, user.role)
    return res.json({
      message: "Login successful",
      userId: user._id,
      role: user.role,
      name: user.name,
      token: token,
    })
  } catch (error) {
    return res.status(401).json({ message: "Google login failed.", error: error.message })
  }
})

app.post("/api/uploads", (req, res, next) => {
  console.log("📁 Upload request received")
  upload.single("file")(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      console.error("❌ Multer error:", err.code, err.message)
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ message: 'File is too large. Maximum size is 100MB' })
      }
      return res.status(400).json({ message: err.message })
    } else if (err) {
      console.error("❌ Upload middleware error:", err.message)
      return res.status(500).json({ message: "Upload failed", error: err.message })
    }

    if (!req.file) {
      console.warn("⚠️  No file provided in upload request")
      return res.status(400).json({ message: "No file uploaded" })
    }

    const fileUrl = `/uploads/${req.file.filename}`
    console.log("✓ File uploaded successfully:", fileUrl)
    res.status(201).json({
      message: "File uploaded",
      url: fileUrl,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
    })
  })
})

app.get("/api/courses", async (req, res) => {
  try {
    const courses = await Course.find({ isPublished: true }).sort({ createdAt: -1 })
    res.json(courses)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch courses", error: error.message })
  }
})

app.get("/api/courses/:id", async (req, res) => {
  try {
    const { id } = req.params
    const course = await Course.findOne({ _id: id, isPublished: true })
    
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }
    
    res.json(course)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch course", error: error.message })
  }
})

app.get("/api/admin/users", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 })
    res.json(users)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch users", error: error.message })
  }
})

app.get("/api/admin/users/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params
    
    const user = await User.findById(id).select('-password')
    if (!user) {
      return res.status(404).json({ message: "User not found" })
    }
    
    res.json(user)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch user", error: error.message })
  }
})

app.delete("/api/admin/users/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params
    
    const userToDelete = await User.findById(id)
    if (!userToDelete) {
      return res.status(404).json({ message: "User not found" })
    }

    if (userToDelete.role === "Admin") {
      const adminCount = await User.countDocuments({ role: "Admin" })
      if (adminCount === 1) {
        return res.status(403).json({ message: "Cannot delete the last admin user" })
      }
    }
    
    const deletedUser = await User.findByIdAndDelete(id)
    
    await Enrollment.deleteMany({ userId: id })
    await Review.deleteMany({ userId: id })
    
    console.log(`✅ User deleted: ${deletedUser.name} (${deletedUser.email})`)
    res.json({ message: "User deleted successfully" })
  } catch (error) {
    res.status(500).json({ message: "Failed to delete user", error: error.message })
  }
})

app.get("/api/admin/courses", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const courses = await Course.find().sort({ createdAt: -1 })
    res.json(courses)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch courses", error: error.message })
  }
})

app.get("/api/admin/courses/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params
    
    const course = await Course.findById(id)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }
    
    res.json(course)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch course", error: error.message })
  }
})

app.post("/api/courses", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { title, description, instructor, category, level, duration, lessons, price, originalPrice, thumbnail } = req.body
    const userId = req.body.userId || req.headers['x-user-id']
    
    if (!title || !description || !instructor || !category) {
      return res.status(400).json({ message: "Please provide title, description, instructor, and category" })
    }

    const normalizedLessons = Array.isArray(lessons) ? lessons : []

    const course = await Course.create({
      title,
      description,
      instructor,
      category,
      level: level || "Beginner",
      duration: duration || "N/A",
      lessons: normalizedLessons,
      price: price || 0,
      originalPrice,
      thumbnail,
      isPublished: true,
      createdBy: userId,
    })

    console.log(`✅ Course created: ${course.title}`)
    res.status(201).json({ message: "Course created successfully", course })
  } catch (error) {
    console.error('❌ Course creation error:', error.message)
    res.status(500).json({ message: "Failed to create course", error: error.message })
  }
})

app.patch("/api/courses/:id", async (req, res) => {
  try {
    const { id } = req.params
    const updates = req.body
    
    const course = await Course.findByIdAndUpdate(id, updates, { new: true })
    
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }
    
    console.log(`✅ Course updated: ${course.title}`)
    res.json({ message: "Course updated successfully", course })
  } catch (error) {
    res.status(500).json({ message: "Failed to update course", error: error.message })
  }
})

app.delete("/api/courses/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params
    
    const course = await Course.findByIdAndDelete(id)
    
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }
    
    console.log(`✅ Course deleted: ${course.title}`)
    res.json({ message: "Course deleted successfully" })
  } catch (error) {
    res.status(500).json({ message: "Failed to delete course", error: error.message })
  }
})

app.post("/api/courses/:courseId/lessons", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { courseId } = req.params
    const { title, videoUrl, videoUrls, description, order } = req.body

    const course = await Course.findById(courseId)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }

    if (!course.lessons) {
      course.lessons = []
    }

    const normalizedVideoUrls = Array.isArray(videoUrls)
      ? videoUrls
      : videoUrl
        ? [videoUrl]
        : []

    const newLesson = {
      title,
      videoUrl: normalizedVideoUrls[0] || videoUrl,
      videoUrls: normalizedVideoUrls,
      description,
      order: order || course.lessons.length,
      materials: []
    }

    course.lessons.push(newLesson)
    await course.save()

    console.log(`✅ Lesson added to course ${course.title}: ${title}`)
    res.json({ message: "Lesson added successfully", lesson: course.lessons[course.lessons.length - 1] })
  } catch (error) {
    res.status(500).json({ message: "Failed to add lesson", error: error.message })
  }
})

app.patch("/api/courses/:courseId/lessons/:lessonId", async (req, res) => {
  try {
    const { courseId, lessonId } = req.params
    const { title, videoUrl, videoUrls, description, order } = req.body

    const course = await Course.findById(courseId)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }

    const lesson = course.lessons.id(lessonId)
    if (!lesson) {
      return res.status(404).json({ message: "Lesson not found" })
    }

    const normalizedVideoUrls = Array.isArray(videoUrls)
      ? videoUrls
      : videoUrl
        ? [videoUrl]
        : null

    if (title) lesson.title = title
    if (normalizedVideoUrls) {
      lesson.videoUrls = normalizedVideoUrls
      lesson.videoUrl = normalizedVideoUrls[0] || lesson.videoUrl
    } else if (videoUrl) {
      lesson.videoUrl = videoUrl
    }
    if (description) lesson.description = description
    if (order !== undefined) lesson.order = order

    await course.save()

    console.log(`✅ Lesson updated: ${lesson.title}`)
    res.json({ message: "Lesson updated successfully", lesson })
  } catch (error) {
    res.status(500).json({ message: "Failed to update lesson", error: error.message })
  }
})

app.delete("/api/courses/:courseId/lessons/:lessonId", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { courseId, lessonId } = req.params

    const course = await Course.findById(courseId)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }

    const lesson = course.lessons.id(lessonId)
    if (!lesson) {
      return res.status(404).json({ message: "Lesson not found" })
    }

    lesson.deleteOne()
    await course.save()

    console.log(`✅ Lesson deleted from course: ${course.title}`)
    res.json({ message: "Lesson deleted successfully" })
  } catch (error) {
    res.status(500).json({ message: "Failed to delete lesson", error: error.message })
  }
})

app.post("/api/courses/:courseId/lessons/:lessonId/materials", async (req, res) => {
  try {
    const { courseId, lessonId } = req.params
    const { name, url, type } = req.body

    const course = await Course.findById(courseId)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }

    const lesson = course.lessons.id(lessonId)
    if (!lesson) {
      return res.status(404).json({ message: "Lesson not found" })
    }

    if (!lesson.materials) {
      lesson.materials = []
    }

    const newMaterial = {
      name,
      url,
      type: type || "other"
    }

    lesson.materials.push(newMaterial)
    await course.save()

    const addedMaterial = lesson.materials[lesson.materials.length - 1]
    console.log(`✅ Material added to lesson: ${lesson.title} - ${name}`)
    console.log(`  - Material ID: ${addedMaterial._id}`)
    res.json({ message: "Material added successfully", material: addedMaterial })
  } catch (error) {
    res.status(500).json({ message: "Failed to add material", error: error.message })
  }
})

app.patch("/api/courses/:courseId/lessons/:lessonId/materials/:materialId", async (req, res) => {
  try {
    const { courseId, lessonId, materialId } = req.params
    const { name, url, type } = req.body

    console.log(`🔍 PATCH Material Update:`)
    console.log(`  - courseId: ${courseId}`)
    console.log(`  - lessonId: ${lessonId}`)
    console.log(`  - materialId: ${materialId}`)

    const course = await Course.findById(courseId)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }

    const lesson = course.lessons.id(lessonId)
    if (!lesson) {
      return res.status(404).json({ message: "Lesson not found" })
    }

    console.log(`  - lesson found: ${lesson.title}`)
    console.log(`  - lesson.materials length: ${lesson.materials.length}`)
    console.log(`  - lesson.materials IDs: ${lesson.materials.map(m => m._id).join(', ')}`)

    let material = lesson.materials.id(materialId)
    
    if (!material) {
      console.log(`  - .id() method didn't find material, trying manual search...`)
      material = lesson.materials.find(m => m._id.toString() === materialId.toString())
    }

    if (!material) {
      console.log(`  - ❌ Material not found with id: ${materialId}`)
      return res.status(404).json({ message: "Material not found" })
    }
    console.log(`  - ✅ Material found`)

    if (name) material.name = name
    if (url) material.url = url
    if (type) material.type = type

    await course.save()

    console.log(`✅ Material updated in lesson: ${lesson.title}`)
    res.json({ message: "Material updated successfully", material })
  } catch (error) {
    res.status(500).json({ message: "Failed to update material", error: error.message })
  }
})

app.delete("/api/courses/:courseId/lessons/:lessonId/materials/:materialId", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { courseId, lessonId, materialId } = req.params

    const course = await Course.findById(courseId)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }

    const lesson = course.lessons.id(lessonId)
    if (!lesson) {
      return res.status(404).json({ message: "Lesson not found" })
    }

    let material = lesson.materials.id(materialId)
    
    if (!material) {
      material = lesson.materials.find(m => m._id.toString() === materialId.toString())
    }

    if (!material) {
      return res.status(404).json({ message: "Material not found" })
    }

    material.deleteOne()
    await course.save()

    console.log(`✅ Material deleted from lesson: ${lesson.title}`)
    res.json({ message: "Material deleted successfully" })
  } catch (error) {
    res.status(500).json({ message: "Failed to delete material", error: error.message })
  }
})

app.post("/api/reviews", async (req, res) => {
  try {
    const { courseId, userId, userName, rating, comment } = req.body

    if (!courseId || !userId || !rating || !comment) {
      return res.status(400).json({ message: "All fields are required" })
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ message: "Rating must be between 1 and 5" })
    }

    const course = await Course.findById(courseId)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }

    const user = await User.findById(userId)
    if (!user) {
      return res.status(404).json({ message: "User not found" })
    }

    const existingReview = await Review.findOne({ courseId, userId })
    if (existingReview) {
      existingReview.rating = rating
      existingReview.comment = comment
      await existingReview.save()
      console.log(`✅ Review updated for course: ${course.title}`)
      return res.json({ message: "Review updated successfully", review: existingReview })
    }

    const review = await Review.create({
      courseId,
      userId,
      userName: userName || user.name,
      rating,
      comment,
    })

    console.log(`✅ Review created for course: ${course.title}`)
    res.status(201).json({ message: "Review submitted successfully", review })
  } catch (error) {
    console.error("❌ Review submission failed:", error)
    res.status(500).json({ message: "Failed to submit review", error: error.message })
  }
})

app.get("/api/reviews/course/:courseId", async (req, res) => {
  try {
    const { courseId } = req.params
    const reviews = await Review.find({ courseId }).sort({ createdAt: -1 })
    res.json(reviews)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch reviews", error: error.message })
  }
})

app.get("/api/reviews/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params
    const reviews = await Review.find({ userId })
      .populate('courseId', 'title thumbnail description')
      .populate('userId', 'name email')
      .sort({ createdAt: -1 })
    res.json(reviews)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch user reviews", error: error.message })
  }
})

app.get("/api/admin/reviews", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const reviews = await Review.find()
      .populate('courseId', 'title thumbnail')
      .populate('userId', 'name email')
      .sort({ createdAt: -1 })
    res.json(reviews)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch reviews", error: error.message })
  }
})

app.delete("/api/reviews/:reviewId", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { reviewId } = req.params
    const review = await Review.findByIdAndDelete(reviewId)
    
    if (!review) {
      return res.status(404).json({ message: "Review not found" })
    }

    console.log(`✅ Review deleted`)
    res.json({ message: "Review deleted successfully" })
  } catch (error) {
    res.status(500).json({ message: "Failed to delete review", error: error.message })
  }
})

app.post("/api/enrollments", async (req, res) => {
  try {
    const { userId, courseId } = req.body

    if (!userId || !courseId) {
      return res.status(400).json({ message: "userId and courseId are required" })
    }

    const course = await Course.findById(courseId)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }

    const existing = await Enrollment.findOne({ userId, courseId })
    if (existing && existing.status === "enrolled") {
      return res.status(409).json({ message: "Already enrolled in this course" })
    }

    if (existing && existing.status === "unenrolled") {
      existing.status = "enrolled"
      existing.unenrolledAt = null
      existing.lastAccessedAt = new Date()
      await existing.save()
      await Course.updateOne({ _id: courseId }, { $inc: { students: 1 } })
      const updatedCourse = await Course.findById(courseId).select("students")
      return res.json({
        message: "Re-enrolled successfully",
        enrollment: existing,
        students: updatedCourse?.students ?? 0,
      })
    }

    const enrollment = await Enrollment.create({
      userId,
      courseId,
      status: "enrolled",
      completedLessons: new Map(),
      completionPercentage: 0,
    })

    await Course.updateOne({ _id: courseId }, { $inc: { students: 1 } })
    const updatedCourse = await Course.findById(courseId).select("students")

    console.log(`✅ User enrolled in course: ${course.title}`)
    res.status(201).json({
      message: "Enrolled successfully",
      enrollment,
      students: updatedCourse?.students ?? 0,
    })
  } catch (error) {
    console.error("❌ Enrollment error:", error)
    res.status(500).json({ message: "Failed to enroll", error: error.message })
  }
})

app.delete("/api/enrollments/:courseId", async (req, res) => {
  try {
    const { courseId } = req.params
    const userId = req.body.userId
    
    if (!userId) {
      return res.status(400).json({ message: "userId is required" })
    }

    const enrollment = await Enrollment.findOne({ userId, courseId })
    if (!enrollment) {
      return res.status(404).json({ message: "Enrollment not found" })
    }

    enrollment.status = "unenrolled"
    enrollment.unenrolledAt = new Date()
    await enrollment.save()

    await Course.updateOne({ _id: courseId, students: { $gt: 0 } }, { $inc: { students: -1 } })
    const updatedCourse = await Course.findById(courseId).select("students")

    console.log(`✅ User unenrolled from course`)
    res.json({ message: "Unenrolled successfully", students: updatedCourse?.students ?? 0 })
  } catch (error) {
    res.status(500).json({ message: "Failed to unenroll", error: error.message })
  }
})

app.get("/api/enrollments/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params
    const enrollments = await Enrollment.find({ userId, status: "enrolled" })
      .populate('courseId', 'title description instructor category level duration thumbnail lessons students')
      .sort({ enrolledAt: -1 })
    
    res.json(enrollments)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch enrollments", error: error.message })
  }
})

app.get("/api/enrollments/course/:courseId", async (req, res) => {
  try {
    const { courseId } = req.params
    const enrollments = await Enrollment.find({ courseId, status: "enrolled" })
      .populate('userId', 'name email')
      .sort({ enrolledAt: -1 })
    
    res.json(enrollments)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch course enrollments", error: error.message })
  }
})

app.get("/api/enrollments/all", async (req, res) => {
  try {
    const enrollments = await Enrollment.find()
      .populate('userId', 'name email')
      .populate('courseId', 'title')
      .sort({ enrolledAt: -1 })
    
    res.json(enrollments)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch enrollments", error: error.message })
  }
})

app.get("/api/enrollments/completed/:userId", async (req, res) => {
  try {
    const { userId } = req.params

    const enrollments = await Enrollment.find({
      userId,
      completionPercentage: 100
    })
      .populate('courseId', 'title description instructor category level duration thumbnail lessons')
      .sort({ enrolledAt: -1 })

    res.json(enrollments)
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch completed courses", error: error.message })
  }
})

app.put("/api/enrollments/progress", async (req, res) => {
  try {
    const { userId, courseId, lessonId, completed } = req.body

    if (!userId || !courseId || !lessonId) {
      return res.status(400).json({ message: "userId, courseId, and lessonId are required" })
    }

    const enrollment = await Enrollment.findOne({ userId, courseId })
    if (!enrollment) {
      return res.status(404).json({ message: "Enrollment not found" })
    }

    const course = await Course.findById(courseId)
    if (!course) {
      return res.status(404).json({ message: "Course not found" })
    }

    enrollment.completedLessons.set(lessonId, completed === true)

    const totalLessons = course.lessons?.length || 0
    if (totalLessons > 0) {
      const completedCount = Array.from(enrollment.completedLessons.values()).filter(Boolean).length
      enrollment.completionPercentage = Math.round((completedCount / totalLessons) * 100)
    }

    enrollment.lastAccessedAt = new Date()
    await enrollment.save()

    console.log(`✅ Enrollment progress updated: ${enrollment.completionPercentage}%`)
    res.json({ message: "Progress updated", enrollment })
  } catch (error) {
    console.error("❌ Progress update error:", error)
    res.status(500).json({ message: "Failed to update progress", error: error.message })
  }
})

app.post("/api/admin/sync-enrollment-counts", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const courses = await Course.find()
    let updated = 0

    for (const course of courses) {
      const enrollmentCount = await Enrollment.countDocuments({
        courseId: course._id,
        status: "enrolled"
      })

      if (course.students !== enrollmentCount) {
        await Course.updateOne(
          { _id: course._id },
          { $set: { students: enrollmentCount } }
        )
        updated++
        console.log(`✅ Updated ${course.title}: ${course.students} → ${enrollmentCount} students`)
      }
    }

    res.json({
      message: "Enrollment counts synchronized successfully",
      coursesUpdated: updated,
      totalCourses: courses.length
    })
  } catch (error) {
    console.error("❌ Sync enrollment counts error:", error)
    res.status(500).json({ message: "Failed to sync enrollment counts", error: error.message })
  }
})

app.use((error, req, res, next) => {
  console.error("❌ Unhandled error:", error)
  res.status(error.status || 500).json({
    message: error.message || "Internal server error",
    error: error.message,
  })
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log(`API server running on port ${PORT}`)
})
