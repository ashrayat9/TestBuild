// app.js
const express = require('express');
const axios = require('axios');
const app = express();
const port = 3000;

app.get('/', (req, res) => {
  res.json({ message: 'Hello from the test app!' });
});

// Test endpoint that makes external API calls
app.get('/test-external', async (req, res) => {
  try {
    const response = await axios.get('https://api.github.com/users/github');
    res.json({ status: 'success', data: response.data });
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
});
