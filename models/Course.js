const mongoose = require("mongoose")

const materialSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    url: { type: String, required: true },
    type: { type: String, enum: ["pdf", "doc", "image", "video", "other"], default: "pdf" },
  },
  { _id: true }
)

const lessonSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    videoUrl: { type: String }, // Legacy single URL
    videoUrls: { type: [String], default: [] },
    description: { type: String },
    order: { type: Number, default: 0 },
    materials: [materialSchema],
  },
  { _id: true }
)

const courseSchema = new mongoose.Schema(
  {
    title: { type: String, required: [true, "Please provide a course title"], trim: true },
    description: { type: String, required: [true, "Please provide a course description"] },
    instructor: { type: String, required: [true, "Please provide instructor name"] },
    category: { type: String, required: [true, "Please select a category"] },
    level: { 
      type: String, 
      enum: ["Beginner", "Intermediate", "Advanced"], 
      default: "Beginner",
      required: true 
    },
    duration: { type: String, default: "N/A" },
    rating: { type: Number, default: 0, min: 0, max: 5 },
    reviews: { type: Number, default: 0 },
    students: { type: Number, default: 0 },
    isNewCourse: { type: Boolean, default: false },
    thumbnail: { type: String },
    isPublished: { type: Boolean, default: false },
    lessons: [lessonSchema],
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true, collection: 'courses' }
)

module.exports = mongoose.model("Course", courseSchema, 'courses')
