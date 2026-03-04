const mongoose = require("mongoose")

const enrollmentSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    courseId: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
    status: { type: String, enum: ["enrolled", "unenrolled"], default: "enrolled" },
    completedLessons: { type: Map, of: Boolean, default: new Map() },
    completionPercentage: { type: Number, default: 0, min: 0, max: 100 },
    enrolledAt: { type: Date, default: Date.now },
    unenrolledAt: { type: Date, default: null },
    lastAccessedAt: { type: Date, default: Date.now },
  },
  { timestamps: true, collection: 'enrollments' }
)

enrollmentSchema.index({ userId: 1, courseId: 1 })
enrollmentSchema.index({ userId: 1, status: 1 })
enrollmentSchema.index({ courseId: 1, status: 1 })

module.exports = mongoose.model("Enrollment", enrollmentSchema, 'enrollments')
