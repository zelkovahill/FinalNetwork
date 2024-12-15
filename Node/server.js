require('dotenv').config();                     // .env 파일에서 환경 변수 로드

const express = require('express');             // 익스프레스 모듈
const mysql = require('mysql2/promise');        // mysql 모듈
const jwt = require('jsonwebtoken');            // JWT 모듈
const bcrypt = require('bcrypt');               // bcrypt 모듈

// 데이터베이스 연결
const pool = mysql.createPool({
    connectionLimit: 10,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    debug: false
});

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// 환경 변수로부터 비밀 키 가져오기
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;



// 회원가입 라우트
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        // 기존 사용자 확인
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);

        if (rows.length > 0) {
            return res.status(400).json({ error: '이미 존재하는 사용자입니다.' });
        }

        // 비밀번호 해싱
        const hashedPassword = await bcrypt.hash(password, 10);

        // 사용자 정보 저장
        await pool.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashedPassword]);

        console.log('User registered:', username);
        res.status(201).json({ message: '회원 가입 성공' });
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({ error: '서버 오류 발생' });
    }
});

// 로그인 요청 시 액세스 토큰과 리프레시 토큰을 클라이언트에서 관리
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.status(400).json({ error: '잘못된 사용자명 또는 비밀번호입니다.' });
        }

        const user = rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(400).json({ error: '잘못된 사용자명 또는 비밀번호입니다.' });
        }

        // 로그인 후 last_login을 현재 시간으로 업데이트
        await pool.execute('UPDATE users SET last_login = ? WHERE username = ?', [new Date(), username]);

        // 액세스 토큰 생성
        const accessToken = jwt.sign({ username: user.username, player_id: user.player_id }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });

        // 리프레시 토큰 생성
        const refreshToken = jwt.sign({ username: user.username, player_id: user.player_id }, REFRESH_TOKEN_SECRET);

        // 리프레시 토큰은 HTTP Only 쿠키에 저장
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,  // 자바스크립트에서 접근 불가
            secure: process.env.NODE_ENV === 'production',  // 프로덕션 환경에서만 HTTPS 사용
            sameSite: 'Strict',  // CSRF 공격 방지
            maxAge: 30 * 24 * 60 * 60 * 1000  // 30일 동안 유효
        });


        res.json({ accessToken });
        // console.log('User logged in:', username);
        console.log('Access Token:', accessToken);
        // console.log('Refresh Token:', refreshToken);
    } catch (err) {
        console.error('로그인 에러:', err);
        res.status(500).json({ error: '서버 오류 발생' });
    }
});

// 토큰 갱신 라우트
app.post('/token', (req, res) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        return res.sendStatus(401);

        jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);

            const accessToken = generateAccessToken({ username: user.username });
            res.json({ accessToken });
        });
    }
});

// 로그아웃 라우트
app.post('/logout', (req, res) => {
    // 리프레시 토큰 쿠키 삭제
    res.clearCookie('refreshToken', { httpOnly: true, secure: true, sameSite: 'Strict' });
    res.status(200).json({ message: '로그아웃 완료' });
});

// 보호된 라우트
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: '보호된 데이터에 접근 성공', user: req.user });
});

// 액세스 토큰 생성 함수
function generateAccessToken(user) {
    return jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
}


// 토큰 인증 미들웨어
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.post('/play', authenticateToken, async (req, res) => {

    const username = req.user.username; // JWT에서 사용자명 가져오기
    const { choice } = req.body;
    const choices = { 0: 'rock', 1: 'paper', 2: 'scissors' };
    const serverChoice = choices[Math.floor(Math.random() * 3)]; // 서버의 선택
    let result;

    console.log('User choice:', choice);
    console.log('Server choice:', serverChoice);
    console.log('User:', username);

    if (choice === serverChoice) {
        result = 'tie';
    }
    else if ((choice === 'rock' && serverChoice === 'scissors') ||
        (choice === 'paper' && serverChoice === 'rock') ||
        (choice === 'scissors' && serverChoice === 'paper')) {
        result = 'win';
    }
    else {
        result = 'lose';
    }

    try {
        // 사용자 데이터 가져오기
        const [userRows] = await pool.execute(`SELECT player_id, wins, losses, ties FROM users WHERE username = ?`, [username]);
        if (userRows.length === 0) {
            return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
        }
        const user = userRows[0];

        // 점수 업데이트
        const column = result === 'win' ? 'wins' : result === 'lose' ? 'losses' : 'ties';
        await pool.execute(`UPDATE users SET ${column} = ${column} + 1 WHERE player_id = ?`, [user.player_id]);

        // 게임 기록 추가
        await pool.execute(
            `INSERT INTO game_history (player_id, user_choice, server_choice, result) VALUES (?, ?, ?, ?)`,
            [user.player_id, choice, serverChoice, result]
        );

        res.json({ result, serverChoice });
    } catch (err) {
        console.error('Error playing game:', err);
        res.status(500).json({ error: '서버 오류 발생' });
    }
});

// 게임 기록을 반환하는 라우트
app.get('/history', authenticateToken, async (req, res) => {
    const username = req.user.username;

    try {
        // 사용자 데이터 가져오기
        const [userRows] = await pool.execute(`SELECT player_id FROM users WHERE username = ?`, [username]);
        if (userRows.length === 0) {
            return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
        }
        const playerId = userRows[0].player_id;

        // 게임 기록 가져오기
        const [historyRows] = await pool.execute(
            `SELECT user_choice, server_choice, result, timestamp 
             FROM game_history 
             WHERE player_id = ? 
             ORDER BY timestamp DESC`,
            [playerId]
        );

        res.json({ history: historyRows });
    } catch (err) {
        console.error('Error fetching history:', err);
        res.status(500).json({ error: '서버 오류 발생' });
    }
});

// 랭킹 조회 라우트
app.get('/ranking', async (req, res) => {
    try {
        // 랭킹 순으로 사용자 데이터 가져오기
        const [rankingRows] = await pool.execute(`
            SELECT username, wins, losses, ties
            FROM users
            ORDER BY wins DESC, losses ASC, ties DESC
            LIMIT 10`);

        // 랭킹 결과 반환
        res.json({ ranking: rankingRows });
    }
    catch (err) {
        console.error('Error fetching ranking:', err);
        res.status(500).json({ error: '서버 오류 발생' });
    }
});




app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});