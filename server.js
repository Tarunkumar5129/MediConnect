require("dotenv").config();
require("./db/conn");
const express = require("express");
const cors = require("cors");
const userRouter = require("./routes/userRoutes");
const doctorRouter = require("./routes/doctorRoutes");
const appointRouter = require("./routes/appointRoutes");
const path = require("path");
const notificationRouter = require("./routes/notificationRouter");

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use("/api/user", userRouter);
app.use("/api/doctor", doctorRouter);
app.use("/api/appointment", appointRouter);
app.use("/api/notification", notificationRouter);
app.use(express.static(path.join(__dirname, "./client/build")));
app.get("/*.js",  (req, res) => res.sendFile(path.join(__dirname, "client/build", req.path)));
app.get("/*.css", (req, res) => res.sendFile(path.join(__dirname, "client/build", req.path)));
app.get("/site.webmanifest", (req, res) =>
  res.sendFile(path.join(__dirname, "client/build", "site.webmanifest"))
);
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "./client/build/index.html"));
});
app.get("/api/health", (req, res) => res.json({ status: "OK" }));
app.listen(port, () => {});
