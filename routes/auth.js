const { Router } = require('express')
const router = Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const { check, validationResult } = require('express-validator')
const User = require('../models/User')

router.post('/register',
  [
    check('email', 'НЕкорректный емайл').isEmail(),
    check('password', 'Пароль не соответсвует требованиям').isLength({ min: 6 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({
          message: 'Некорректные данные',
          errors: errors.array()
        })
      }
      const { email, password } = req.body
      const candidate = await User.findOne({ email })
      if (candidate) {
        return res.status(400).json({ message: 'Такой пользователь уже существует' })
      }
      const hashedPassword = await bcrypt.hash(password, 12)
      const user = new User({ email, passord: hashedPassword })
      await user.save()
      res.status(201).json({ message: 'User created' })
    } catch (e) {
      res.status(500).json({ message: 'Что-то пошло не так' })
    }
  })

router.post('/login',
  [
    check('email', 'Некорректный емайл').normalizeEmail().isEmail(),
    check('password', 'Введите пароль').exists()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({
          message: 'Некорректные данные',
          errors: errors.array()
        })
      }
      const { email, password } = req.body
      const user = await User.findOne({ email })
      if (!user) {
        return res.status(400).json({ message: 'Пользователь не найден' })
      }
      const isPassword = bcrypt.compare(password, user.password)
      if (!isPassword) {
        return res.status(400).json({ message: 'Неверный пароль' })
      }
      const token = jwt.sign(
        { userId: user.id },
        config.get('jwtSecret'),
        { expiresIn: '1h' }
      )
      res.json({ token, userId: user.id })

    } catch (e) {
      res.status(500).json({ message: 'Что-то пошло не так' })
    }
  })

module.exports = router