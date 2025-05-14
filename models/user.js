const mongoose = require("mongoose");

mongoose.connect(`mongodb://127.0.0.1:27017/dataassociation`);

const userSchema = mongoose.Schema({
  username: String,
  name: String,
  age: Number,
  email: String,
  password: String,
  posts: [{ type: mongoose.Schema.Types.ObjectId, ref: "post" }], //type: mongoose.Schema.Types.ObjectId => means that the type is of the id that gets generated when we create a document
}); //ref: "post" => means that it is referencing to the post model that we created.

module.exports = mongoose.model("user", userSchema);
