import mongoose from "mongoose";

const transactionSchema = new mongoose.Schema (
  {
    type: { type: String, required: true },       
    category: { type: String, required: true },
    amount: { type: Number, required: true },
    date: { type: Date, required: true },    
    description: { type: String },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }
  },
  {
    collection: "Transactions"
  }
);

export default mongoose.model("Transaction", transactionSchema);
