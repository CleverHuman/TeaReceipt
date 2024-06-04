import createServer from "./index.js";

const PORT = process.env.PORT || 8000;

const app = createServer();

app.listen(PORT, () => {
  console.log(`listening to port ${PORT}`);
}).on("error", (err) => {
  console.error(err);
  process.exit(1);
});