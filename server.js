const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Konfigurasi Session
app.use(session({
    secret: 'kunci-rahasia-perpus',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// KONEKSI KE DATABASE MYSQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',      
    password: '',      
    database: 'nssbs_library'
});

db.connect((err) => {
    if (err) {
        console.error('Gagal terhubung ke database MySQL:', err.message);
        return;
    }
    console.log('Berhasil terhubung ke database MySQL (nssbs_library)');
    buatAkunAdminOtomatis(); // Jalankan fungsi auto-create akun
});

// 🔥 FUNGSI OTOMATIS MEMBUAT AKUN ADMIN JIKA BELUM ADA / RUSAK
async function buatAkunAdminOtomatis() {
    const usernameAdmin = 'admin';
    const passwordPolos = 'admin123';

    db.query('SELECT * FROM users WHERE username = ?', [usernameAdmin], async (err, results) => {
        if (err) return console.error(err);

        // Jika admin sudah ada, kita hapus dulu yang lama agar hash-nya diperbarui dengan yang segar
        if (results.length > 0) {
            db.query('DELETE FROM users WHERE username = ?', [usernameAdmin]);
        }

        // Generate hash bcrypt langsung di dalam Node.js (100% Aman & Akurat)
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(passwordPolos, salt);

        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [usernameAdmin, passwordHash], (err) => {
            if (err) {
                console.error('Gagal membuat ulang akun admin:', err.message);
            } else {
                console.log('--> Akun Admin otomatis diperbarui oleh Node.js!');
                console.log('--> Username: admin | Password: admin123');
            }
        });
    });
}

// Middleware Cek Auth
const kuncianAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ message: "Silahkan login terlebih dahulu!" });
    }
};

// API: Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ message: "Error server" });
        if (results.length === 0) return res.status(400).json({ message: "Username tidak ditemukan" });

        const user = results[0];
        
        // Komparasi Hash
        const passwordCocok = await bcrypt.compare(password, user.password);
        
        if (!passwordCocok) return res.status(400).json({ message: "Password salah" });

        req.session.user = { username: user.username };
        res.json({ message: "Login berhasil", user: req.session.user });
    });
});

// API: Cek Status Login
app.get('/api/auth/status', (req, res) => {
    if (req.session.user) {
        res.json({ isLoggedIn: true, user: req.session.user });
    } else {
        res.json({ isLoggedIn: false });
    }
});

// API: Logout
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: "Logout berhasil" });
});

// API: Ambil semua buku
app.get('/api/buku', (req, res) => {
    db.query('SELECT * FROM buku', (err, results) => {
        if (err) return res.status(500).json({ message: "Gagal mengambil data" });
        res.json(results);
    });
});

// API: Tambah buku baru
app.post('/api/buku', kuncianAuth, (req, res) => {
    const { judul, penulis } = req.body;
    if (!judul || !penulis) return res.status(400).json({ message: "Data tidak lengkap" });

    db.query('INSERT INTO buku (judul, penulis) VALUES (?, ?)', [judul, penulis], (err, result) => {
        if (err) return res.status(500).json({ message: "Gagal menyimpan buku" });
        res.status(201).json({ id: result.insertId, judul, penulis, dipinjam: false });
    });
});

// API: Pinjam/Kembalikan Buku
app.patch('/api/buku/:id/status', kuncianAuth, (req, res) => {
    const id = parseInt(req.params.id);

    db.query('SELECT dipinjam FROM buku WHERE id = ?', [id], (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ message: "Buku tidak ditemukan" });

        const statusBaru = !results[0].dipinjam;

        db.query('UPDATE buku SET dipinjam = ? WHERE id = ?', [statusBaru, id], (err) => {
            if (err) return res.status(500).json({ message: "Gagal mengupdate status" });
            res.json({ message: "Status diperbarui" });
        });
    });
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});