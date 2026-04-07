const fs = require('fs');
const http = require('http');

http.get('http://localhost:3000', (res) => {
  console.log('Status code:', res.statusCode);
});
