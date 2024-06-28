// server.js
const express = require('express');
const mongoose = require('mongoose');
const User = require('./models/user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

mongoose.connect('mongodb://localhost:27017/yourdbname', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const JWT_SECRET = 'your_jwt_secret';

// User Registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = new User({ email, password });
    await user.save();
    res.status(201).send('User registered');
  } catch (error) {
    res.status(400).send('Error registering user');
  }
});

// User Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(400).send('Invalid credentials');
  }
});

// Password Reset Request
app.post('/password-reset', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (user) {
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '15m' });
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'your-email@gmail.com',
        pass: 'your-email-password',
      },
    });

    const mailOptions = {
      from: 'your-email@gmail.com',
      to: user.email,
      subject: 'Password Reset',
      text: `To reset your password, click the following link: http://yourfrontend.com/reset-password/${token}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).send('Error sending email');
      }
      res.send('Password reset email sent');
    });
  } else {
    res.status(400).send('Email not found');
  }
});

// Password Reset
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (user) {
      user.password = newPassword;
      await user.save();
      res.send('Password reset successfully');
    } else {
      res.status(400).send('Invalid token');
    }
  } catch (error) {
    res.status(400).send('Invalid or expired token');
  }
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});