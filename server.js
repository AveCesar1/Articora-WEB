// Importaciones de paquetes necesarios
// Aquí importamos las librerías que vamos a usar en el servidor
const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const path = require('path')
const Database = require('better-sqlite3')
require('dotenv').config()




// --- BASE DE DATOS ---
// Abrimos (o creamos) el archivo de base de datos SQLite
const database = new Database('database.sql')
// Ajuste de rendimiento de SQLite (modo WAL)
database.pragma('journal_mode = WAL')


// Asegurarnos de que la tabla de usuarios exista
// Esta tabla solo guarda el id, el nombre de usuario y la contraseña encriptada
const createUserTable = database.prepare(`
  CREATE TABLE IF NOT EXISTS Usuario (
    Usuario_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Nombre TEXT NOT NULL UNIQUE,
    Contrasenia TEXT NOT NULL
  )
`)
createUserTable.run()



// --- APLICACIÓN ---
// Inicializamos la aplicación Express
const app = express()
// Middleware para leer formularios (req.body)
app.use(express.urlencoded({ extended: false }))
// Servir archivos estáticos desde la carpeta "public" (CSS, JS, imágenes, etc.)
app.use(express.static(path.join(__dirname, 'public')))
// Middleware para manejar cookies
app.use(cookieParser())




// --- MIDDLEWARE: decodificar token de sesión si existe ---
// Este middleware corre en cada petición y busca una cookie llamada ART_R.
// Si existe y es válida, guardamos los datos del usuario en req.user para usar más adelante.
app.use((req, res, next) => {
  req.user = false
  const token = req.cookies && req.cookies.ART_R
  if (token && process.env.JWTSECRET) {
    try {
      const decoded = jwt.verify(token, process.env.JWTSECRET)
      // Guardamos la información relevante del token en req.user
      req.user = {
        userId: decoded.userid,
        username: decoded.username,
        exp: decoded.exp,
        iat: decoded.iat
      }
    } catch (e) {
      // Token inválido: no hacemos nada, el usuario no está logueado
      req.user = false
    }
  }
  next()
})




// --- FUNCIONES AUXILIARES ---
// sanitizeData: limpia cadenas de texto para eliminar etiquetas <script>, backslashes y espacios innecesarios.
// Es una medida básica para evitar inyecciones simples o entradas maliciosas desde formularios.
function sanitizeData(input) {
  if (!input || typeof input !== 'string') return ''
  // Eliminamos cualquier etiqueta <script> y su contenido
  let sanitized = input.replace(/<script\b[^>]*>(.*?)<\/script>/gi, '')
  // Eliminamos backslashes (\)
  sanitized = sanitized.replace(/\\/g, '')
  // Quitamos espacios al inicio y final
  return sanitized.trim()
}





// --- RUTAS PÚBLICAS ---
// Servimos páginas HTML estáticas que deben estar en la carpeta "views".
// Estas rutas muestran formularios y contenido estático, no usan plantillas EJS.

// Página principal (puede mostrar información diferente según si el usuario está logueado)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'))
})

// Página de login (formulario para iniciar sesión)
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'))
})

// Página de registro (formulario para crear cuenta)
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'))
})

// Ruta para cerrar sesión: borramos la cookie y redirigimos al login
app.get('/logout', (req, res) => {
  res.clearCookie('ART_R')
  res.redirect('/login')
})




// --- AUTENTICACIÓN: LOGIN (POST) ---
// Esta ruta procesa el formulario de inicio de sesión.
// Pasos: limpiar entrada, buscar usuario en BD, comparar contraseña y crear cookie JWT.
app.post('/login', (req, res) => {
  const username = sanitizeData(req.body.username)
  const password = sanitizeData(req.body.password)

  if (!username || !password) {
    return res.status(400).send('Invalid credentials')
  }

  const userSearch = database.prepare('SELECT * FROM Usuario WHERE Nombre = ?')
  const user = userSearch.get(username)
  if (!user) {
    // Usuario no encontrado en la base de datos
    return res.status(400).send('User not found')
  }

  // Comparamos la contraseña enviada con la contraseña encriptada en la BD
  const match = bcrypt.compareSync(password, user.Contrasenia)
  if (!match) {
    return res.status(400).send('Incorrect password')
  }

  // Si todo está bien, generamos un token JWT con información mínima y fecha de expiración
  const token = jwt.sign({
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    userid: user.Usuario_ID,
    username: user.Nombre
  }, process.env.JWTSECRET || 'changeme')

  // Guardamos el token en una cookie HTTP-only para mantener la sesión
  res.cookie('ART_R', token, {
    httpOnly: true,
    // secure: false para desarrollo local; cambiar a true en producción con HTTPS
    secure: false,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24
  })

  // Redirigimos al inicio después de iniciar sesión
  res.redirect('/')
})




// --- AUTENTICACIÓN: REGISTRO (POST) ---
// Esta ruta crea un nuevo usuario en la base de datos y lo loguea automáticamente.
// Pasos: validar entrada, verificar que el usuario no exista, encriptar contraseña, insertar y crear cookie.
app.post('/register', (req, res) => {
  const username = sanitizeData(req.body.username)
  const password = sanitizeData(req.body.password)

  // Validaciones básicas para que los nombres y contraseñas sean razonables
  if (!username || username.length < 3 || !/^[a-zA-Z0-9]+$/.test(username)) {
    return res.status(400).send('Invalid username')
  }
  if (!password || password.length < 8) {
    return res.status(400).send('Invalid password')
  }

  // Comprobamos si ya existe el nombre de usuario en la BD
  const exists = database.prepare('SELECT 1 FROM Usuario WHERE Nombre = ?').get(username)
  if (exists) {
    return res.status(400).send('Username already taken')
  }

  // Encriptamos la contraseña antes de guardarla
  const salt = bcrypt.genSaltSync(10)
  const hashed = bcrypt.hashSync(password, salt)

  const insert = database.prepare('INSERT INTO Usuario (Nombre, Contrasenia) VALUES (?, ?)')
  const result = insert.run(username, hashed)

  // Recuperamos el usuario recién creado para generar el token
  const lookup = database.prepare('SELECT * FROM Usuario WHERE Usuario_ID = ?')
  const newUser = lookup.get(result.lastInsertRowid)

  const token = jwt.sign({
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    userid: newUser.Usuario_ID,
    username: newUser.Nombre
  }, process.env.JWTSECRET || 'changeme')

  // Guardamos la cookie de sesión
  res.cookie('ART_R', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24
  })

  // Redirigimos al inicio luego del registro
  res.redirect('/')
})


// No me ves


// --- INICIAR SERVIDOR ---
// Le decimos a Express que escuche en el puerto 8080
app.listen(8080, () => console.log('Server running on http://localhost:8080'))