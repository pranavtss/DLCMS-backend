const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const User = require("./models/User")

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/dlcms"
const ADMIN_SECRET = process.env.ADMIN_SECRET || "dlcms-admin-2026"

async function seedAdmin() {
  try {
    await mongoose.connect(MONGO_URI)
    console.log("MongoDB connected")

    const adminEmail = "admin@dlcms"
    const existing = await User.findOne({ email: adminEmail })
    
    if (existing) {
      console.log("Admin account already exists.")
      process.exit(0)
    }

    const hashed = await bcrypt.hash("admin", 10)
    await User.create({
      name: "Admin",
      email: adminEmail,
      password: hashed,
      role: "Admin",
    })

    console.log("Admin account created successfully")
    console.log("Email: admin@dlcms")
    console.log("Password: admin")
    process.exit(0)
  } catch (error) {
    console.error("Seed failed:", error.message)
    process.exit(1)
  }
}
seedAdmin()
