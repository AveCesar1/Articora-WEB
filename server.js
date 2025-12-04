// Dependencias y configuración inicial
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const Database = require('better-sqlite3');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config();

///////////////////
// BASE DE DATOS //
///////////////////
const database = new Database('database.sql');
database.pragma('journal_mode = WAL');

// Usuario: ID, Nombre, Contrasenia (hashed), Email, Descripcion, FotoPerfil
const createUserTable = database.prepare(`
  CREATE TABLE IF NOT EXISTS Usuario (
    Usuario_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Nombre TEXT NOT NULL UNIQUE,
    Contrasenia TEXT NOT NULL,
    Email TEXT,
    Descripcion TEXT DEFAULT 'Hola soy un usuario de la plataforma de Artícora! Me gusta leer y compartir mis ideas con la gente.',
    FotoPerfil TEXT DEFAULT 'Imagenes/fotodeperfil.png'
  )
`);
createUserTable.run();

// Publicacion: ID, Usuario_ID (FK), Titulo, Tipo, Autores, Portada, Vinculo, Fecha
const createPublicacionTable = database.prepare(`
  CREATE TABLE IF NOT EXISTS Publicacion (
    Publicacion_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Usuario_ID INTEGER NOT NULL,
    Titulo TEXT NOT NULL,
    Tipo TEXT NOT NULL,
    Autores TEXT NOT NULL,
    Portada TEXT DEFAULT 'Imagenes/LibroIcono.png',
    Vinculo TEXT,
    Fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (Usuario_ID) REFERENCES Usuario(Usuario_ID)
  )
`);
createPublicacionTable.run();


// Calificacion: ID, Publicacion_ID (FK), Usuario_ID (FK), Puntuacion, Comentario, Fecha
const createCalificacionTable = database.prepare(`
  CREATE TABLE IF NOT EXISTS Calificacion (
    Calificacion_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Publicacion_ID INTEGER NOT NULL,
    Usuario_ID INTEGER NOT NULL,
    Puntuacion INTEGER NOT NULL CHECK (Puntuacion >= 1 AND Puntuacion <= 5),
    Comentario TEXT,
    Fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (Publicacion_ID) REFERENCES Publicacion(Publicacion_ID),
    FOREIGN KEY (Usuario_ID) REFERENCES Usuario(Usuario_ID),
    UNIQUE(Publicacion_ID, Usuario_ID)
  )
`);
createCalificacionTable.run();

// Favorito: ID, Publicacion_ID (FK), Usuario_ID (FK), Fecha
const createFavoritoTable = database.prepare(`
  CREATE TABLE IF NOT EXISTS Favorito (
    Favorito_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Publicacion_ID INTEGER NOT NULL,
    Usuario_ID INTEGER NOT NULL,
    Fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (Publicacion_ID) REFERENCES Publicacion(Publicacion_ID),
    FOREIGN KEY (Usuario_ID) REFERENCES Usuario(Usuario_ID),
    UNIQUE(Publicacion_ID, Usuario_ID)
  )
`);
createFavoritoTable.run();

// Configuración de Express y middlewares
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

////////////////
// MIDDLEWARE //
////////////////

// Configuración de Multer para manejo de archivos
// -> Multer es una librería para manejar subida de archivos en formularios
// -> Se van a guardar en /public/uploads con un nombre único
// Restricciones:
// -> Tamaño máximo: 5MB
// -> Tipos permitidos: jpeg, jpg, png, gif


// Configuración de almacenamiento
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'public', 'uploads');
    if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});


// Filtro de archivos para permitir solo imágenes
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb(new Error('Solo se permiten imágenes'));
  }
});

// Middleware para autenticar usuario mediante JWT en cookies
app.use((req, res, next) => {
  req.user = false;
  const token = req.cookies && req.cookies.ART_R;
  const secret = process.env.JWTSECRET || 'changeme';

  if (token) {
    try {
      const decoded = jwt.verify(token, secret);
      req.user = {
        userId: decoded.userId,
        username: decoded.username,
        exp: decoded.exp,
        iat: decoded.iat
      };
    } catch (e) {
      req.user = false;
    }
  }
  next();
});

// Función para sanitizar entradas de usuario
function sanitizeData(input) {
  if (!input || typeof input !== 'string') return '';
  let sanitized = input.replace(/<script\b[^>]*>(.*?)<\/script>/gi, '');
  sanitized = sanitized.replace(/\\/g, '');
  return sanitized.trim();
}



////////////////
// RUTAS WEB  //
////////////////

app.get('/', (req, res) => 
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);
app.get('/login', (req, res) => 
  res.sendFile(path.join(__dirname, 'public', 'login.html'))
);
app.get('/register', (req, res) => 
  res.sendFile(path.join(__dirname, 'public', 'register.html'))
);
app.get('/profile', (req, res) => 
  res.sendFile(path.join(__dirname, 'public', 'profile.html'))
);
app.get('/select-source', (req, res) => 
  res.sendFile(path.join(__dirname, 'public', 'select-source.html'))
);
app.get('/view', (req, res) => 
  res.sendFile(path.join(__dirname, 'public', 'view.html'))
);
app.get('/upload', (req, res) => 
  res.sendFile(path.join(__dirname, 'public', 'upload.html'))
);
app.get('/favorites', (req, res) => 
  res.sendFile(path.join(__dirname, 'public', 'favorites.html'))
);

app.get('/logout', (req, res) => {
  res.clearCookie('ART_R');
  res.redirect('/login');
});



///////////////
// RUTAS API //
///////////////

// Login: Conseguir credenciales, generar token JWT y establecer cookie
app.post('/login', (req, res) => {
  const username = sanitizeData(req.body.username);
  const password = sanitizeData(req.body.password);

  if (!username || !password) 
    return res.status(400).send('Credenciales inválidas');

  const userSearch = database.prepare('SELECT * FROM Usuario WHERE Nombre = ?');
  const user = userSearch.get(username);
  if (!user) 
    return res.status(400).send('Usuario no encontrado');

  const match = bcrypt.compareSync(password, user.Contrasenia);
  if (!match) 
    return res.status(400).send('Contraseña incorrecta');

  const token = jwt.sign({
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
    userId: user.Usuario_ID,
    username: user.Nombre
  }, process.env.JWTSECRET || 'changeme');

  res.cookie('ART_R', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24 * 7
  });

  res.redirect('/');
});


// Registro: Crear nuevo usuario, generar token JWT y establecer cookie
app.post('/register', (req, res) => {
  const username = sanitizeData(req.body.username);
  const password = sanitizeData(req.body.password);
  const email = sanitizeData(req.body.email) || '';

  if (!username || username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).send('Nombre de usuario inválido (mínimo 3 caracteres, solo letras, números y guiones bajos)');
  }
  if (!password || password.length < 8) 
    return res.status(400).send('Contraseña inválida (mínimo 8 caracteres)');

  const exists = database.prepare('SELECT 1 FROM Usuario WHERE Nombre = ?').get(username);
  if (exists) 
    return res.status(400).send('El nombre de usuario ya está en uso');

  const salt = bcrypt.genSaltSync(10);
  const hashed = bcrypt.hashSync(password, salt);

  const insert = database.prepare('INSERT INTO Usuario (Nombre, Contrasenia, Email) VALUES (?, ?, ?)');
  const result = insert.run(username, hashed, email);

  const lookup = database.prepare('SELECT * FROM Usuario WHERE Usuario_ID = ?');
  const newUser = lookup.get(result.lastInsertRowid);

  const token = jwt.sign({
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
    userId: newUser.Usuario_ID,
    username: newUser.Nombre
  }, process.env.JWTSECRET || 'changeme');

  res.cookie('ART_R', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24 * 7
  });

  res.redirect('/');
});


// Crear nueva publicación
app.post('/api/publicacion', upload.single('portada'), (req, res) => {
  if (!req.user) 
    return res.status(401).json({ error: 'No autenticado' });

  const { titulo, tipo, autores, vinculo } = req.body;
  const portada = req.file ? 'uploads/' + req.file.filename : 'Imagenes/LibroIcono.png';

  if (!titulo || !tipo || !autores) 
    return res.status(400).json({ error: 'Faltan campos requeridos' });

  const insert = database.prepare(`
    INSERT INTO Publicacion (Usuario_ID, Titulo, Tipo, Autores, Portada, Vinculo)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const result = insert.run(req.user.userId, sanitizeData(titulo), sanitizeData(tipo),
    sanitizeData(autores), portada, sanitizeData(vinculo || ''));

  res.json({ success: true, publicacionId: result.lastInsertRowid });
});


// Obtener lista de publicaciones con paginación y búsqueda
app.get('/api/publicaciones', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;
  const search = req.query.search ? `%${sanitizeData(req.query.search)}%` : null;

  let query = `SELECT p.*, u.Nombre as UsuarioNombre FROM Publicacion p 
               JOIN Usuario u ON p.Usuario_ID = u.Usuario_ID`;
  let countQuery = `SELECT COUNT(*) as total FROM Publicacion p JOIN Usuario u ON p.Usuario_ID = u.Usuario_ID`;

  const params = [];
  const countParams = [];

  if (search) {
    query += ` WHERE p.Titulo LIKE ? OR p.Autores LIKE ? OR p.Tipo LIKE ?`;
    countQuery += ` WHERE p.Titulo LIKE ? OR p.Autores LIKE ? OR p.Tipo LIKE ?`;
    params.push(search, search, search);
    countParams.push(search, search, search);
  }

  query += ` ORDER BY p.Fecha DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  const publicaciones = database.prepare(query).all(...params);

  const totalResult = database.prepare(countQuery).get(...countParams);
  const total = totalResult.total;

  publicaciones.forEach(pub => {
    const avg = database.prepare('SELECT AVG(Puntuacion) as promedio FROM Calificacion WHERE Publicacion_ID = ?')
      .get(pub.Publicacion_ID);
    pub.puntuacionPromedio = avg.promedio ? parseFloat(avg.promedio.toFixed(1)) : 0;

    if (req.user) {
      const favorito = database.prepare('SELECT 1 FROM Favorito WHERE Publicacion_ID = ? AND Usuario_ID = ?')
        .get(pub.Publicacion_ID, req.user.userId);
      pub.esFavorito = !!favorito;
    }
  });

  res.json({ publicaciones, total, page, totalPages: Math.ceil(total / limit) });
});


// Obtener detalles de una publicación específica
app.get('/api/publicacion/:id', (req, res) => {
  const publicacion = database.prepare(`
    SELECT p.*, u.Nombre as UsuarioNombre FROM Publicacion p 
    JOIN Usuario u ON p.Usuario_ID = u.Usuario_ID 
    WHERE p.Publicacion_ID = ?
  `).get(req.params.id);

  if (!publicacion) return res.status(404).json({ error: 'Publicación no encontrada' });

  const calificaciones = database.prepare(`
    SELECT c.*, u.Nombre FROM Calificacion c 
    JOIN Usuario u ON c.Usuario_ID = u.Usuario_ID 
    WHERE c.Publicacion_ID = ? ORDER BY c.Fecha DESC
  `).all(req.params.id);

  const avg = database.prepare('SELECT AVG(Puntuacion) as promedio FROM Calificacion WHERE Publicacion_ID = ?')
    .get(req.params.id);
  publicacion.puntuacionPromedio = avg.promedio ? parseFloat(avg.promedio.toFixed(1)) : 0;

  if (req.user) {
    const userRating = database.prepare('SELECT * FROM Calificacion WHERE Publicacion_ID = ? AND Usuario_ID = ?')
      .get(req.params.id, req.user.userId);
    publicacion.calificacionUsuario = userRating || null;

    const favorito = database.prepare('SELECT 1 FROM Favorito WHERE Publicacion_ID = ? AND Usuario_ID = ?')
      .get(req.params.id, req.user.userId);
    publicacion.esFavorito = !!favorito;
  }

  res.json({ publicacion, calificaciones });
});


// Calificar una publicación
app.post('/api/calificar', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'No autenticado' });

  const { publicacionId, puntuacion, comentario } = req.body;

  if (!publicacionId || !puntuacion || puntuacion < 1 || puntuacion > 5) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  const insert = database.prepare(`
    INSERT OR REPLACE INTO Calificacion (Publicacion_ID, Usuario_ID, Puntuacion, Comentario)
    VALUES (?, ?, ?, ?)
  `);

  insert.run(publicacionId, req.user.userId, parseInt(puntuacion), sanitizeData(comentario || ''));
  res.json({ success: true });
});


// Agregar o quitar favorito
app.post('/api/favorito', (req, res) => {
  if (!req.user) 
    return res.status(401).json({ error: 'No autenticado' });

  const { publicacionId, accion } = req.body;
  if (!publicacionId || !['agregar', 'quitar'].includes(accion)) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  if (accion === 'agregar') {
    const insert = database.prepare('INSERT OR IGNORE INTO Favorito (Publicacion_ID, Usuario_ID) VALUES (?, ?)');
    insert.run(publicacionId, req.user.userId);
  } else {
    const del = database.prepare('DELETE FROM Favorito WHERE Publicacion_ID = ? AND Usuario_ID = ?');
    del.run(publicacionId, req.user.userId);
  }

  res.json({ success: true });
});


// Obtener lista de favoritos del usuario
app.get('/api/favoritos', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'No autenticado' });

  const publicaciones = database.prepare(`
    SELECT p.*, u.Nombre as UsuarioNombre FROM Publicacion p
    JOIN Favorito f ON p.Publicacion_ID = f.Publicacion_ID
    JOIN Usuario u ON p.Usuario_ID = u.Usuario_ID
    WHERE f.Usuario_ID = ? ORDER BY f.Fecha DESC
  `).all(req.user.userId);

  publicaciones.forEach(pub => {
    const avg = database.prepare('SELECT AVG(Puntuacion) as promedio FROM Calificacion WHERE Publicacion_ID = ?')
      .get(pub.Publicacion_ID);
    pub.puntuacionPromedio = avg.promedio ? parseFloat(avg.promedio.toFixed(1)) : 0;
  });

  res.json({ publicaciones });
});


// Obtener perfil de usuario y sus publicaciones
app.get('/api/usuario/:id', (req, res) => {
  const usuario = database.prepare('SELECT Usuario_ID, Nombre, Email, Descripcion, FotoPerfil FROM Usuario WHERE Usuario_ID = ?')
    .get(req.params.id);

  if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });

  const publicaciones = database.prepare(`
    SELECT * FROM Publicacion WHERE Usuario_ID = ? ORDER BY Fecha DESC
  `).all(req.params.id);

  publicaciones.forEach(pub => {
    const avg = database.prepare('SELECT AVG(Puntuacion) as promedio FROM Calificacion WHERE Publicacion_ID = ?')
      .get(pub.Publicacion_ID);
    pub.puntuacionPromedio = avg.promedio ? parseFloat(avg.promedio.toFixed(1)) : 0;
  });

  res.json({ usuario, publicaciones });
});


// Obtener perfil del usuario autenticado
app.get('/api/me', (req, res) => {
  if (req.user) {
    const usuario = database.prepare('SELECT Usuario_ID, Nombre, Email, Descripcion, FotoPerfil FROM Usuario WHERE Usuario_ID = ?')
      .get(req.user.userId);
    return res.json({ ...usuario, isAuthenticated: true });
  }
  res.json({ username: null, isAuthenticated: false });
});


// Actualizar perfil del usuario autenticado
app.put('/api/perfil', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'No autenticado' });

  const { descripcion } = req.body;
  const update = database.prepare('UPDATE Usuario SET Descripcion = ? WHERE Usuario_ID = ?');
  update.run(sanitizeData(descripcion || ''), req.user.userId);

  res.json({ success: true });
});




app.listen(8080, () =>
  console.log('Servidor ejecutándose en http://localhost:8080')
);