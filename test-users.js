const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('portal.db');

db.all("SELECT * FROM users", (err, rows) => {
    console.log(rows);
});
