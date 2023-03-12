const express = require('express');
const userRouter = require('./user.router');
const router = express.Router();
const sendEmail = require('../utils/senEmail')

// colocar las rutas aquí
router.use('/users', userRouter)



module.exports = router;