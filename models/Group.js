const mongoose = require("mongoose");

const groupSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    participants: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
        }
    ],
    messages: [
        {
            sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
            name: { type: String, required: true },
            text: String,
            timestamp: { type: Date, default: Date.now }
        }
    ],
    lastMessageAt: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });

const Group = mongoose.model("Group", groupSchema);

module.exports = Group;
