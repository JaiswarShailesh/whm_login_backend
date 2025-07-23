// hash-password.js
const bcrypt = require("bcrypt");

(async () => {
  const password = "test@123";
  const hash = await bcrypt.hash(password, 10);
  console.log("Hashed password:", hash);
})();

// $2b$10$RzYS1CTHCxiTgxEbwpXPl.sbWTHkPGtuyaDjalYbz8A2HDeZ65.My