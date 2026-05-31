import app from "./src/app.js";
import connectDB from "./src/config/database.js";

async function callDB() {
  await connectDB();
}

callDB();

app.listen(3000, () => {
  console.log("Server is running at port 3000.")
})