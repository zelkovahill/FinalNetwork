# 가위 바위 보
## 1.1 기획 의도

|항목|설명|
|-|-|
|게임명|**가위 바위 보!**|
|클라이언트|**`Unity`**|
|서버|**`Node.js`**|
|데이터베이스|**`MySQL`**|

실시간 랭킹 시스템과 자동 결과 계산을 제공하는 간단한 가위바위보 게임입니다. <br>
AI와 경쟁을 통해 전적를 기록하고, 결과는 자동으로 계산되어 실시간 랭킹이 갱신됩니다.

<br>

## 1.2 개발 과정
### 데이터베이스
``` sql
-- #1 데이터베이스 생성
create database Game_DB_02;

-- #2 데이터베이스 사용
use Game_DB_02;

-- #3 유저 테이블 생성
create table if not exists users(
	player_id int auto_increment primary key comment '사용자 ID 번호',
    username varchar(50) unique not null comment '사용자 닉네임',
	password_hash varchar(255) not null comment '사용자 비밀번호 (암호화)',
    created_at timestamp default current_timestamp comment '생성 날짜',
    last_login timestamp comment '마지막 로그인 날짜'
);

-- #4 users 테이블에 전적 추가
ALTER TABLE users
ADD wins INT DEFAULT 0,
ADD losses INT DEFAULT 0,
ADD ties INT DEFAULT 0;

-- #5 게임 기록 테이블 추가
CREATE TABLE IF NOT EXISTS game_history (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '게임 기록 ID',
    player_id INT NOT NULL COMMENT '사용자 ID 번호',
    user_choice VARCHAR(50) NOT NULL COMMENT '사용자가 선택한 값',
    server_choice VARCHAR(50) NOT NULL COMMENT '서버가 선택한 값',
    result VARCHAR(50) NOT NULL COMMENT '결과 (win, lose, tie)',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '게임 실행 시간',
    FOREIGN KEY (player_id) REFERENCES users(player_id) ON DELETE CASCADE
);
```

<br>

#### 1. 데이터베이스 생성
``` sql
create database Game_DB_02;
```
게임의 데이터를 저장하기 위해 Game_DB_02라는 데이터베이스를 생성했습니다. <br>
이 데이터베이스는 게임과 관련된 사용자 정보와 게임 기록을 관리합니다.

<br>

#### 2. 사용자 테이블 생성
``` sql
CREATE TABLE IF NOT EXISTS users (
    player_id INT AUTO_INCREMENT PRIMARY KEY COMMENT '사용자 ID 번호',
    username VARCHAR(50) UNIQUE NOT NULL COMMENT '사용자 닉네임',
    password_hash VARCHAR(255) NOT NULL COMMENT '사용자 비밀번호 (암호화)',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '생성 날짜',
    last_login TIMESTAMP COMMENT '마지막 로그인 날짜'
);
```
users 테이블은 사용자 정보를 저장합니다. <br>
이 테이블에는 사용자 ID, 닉네임, 암호화된 비밀번호, 생성 일자, 마지막 로그인 시간을 포함하여 사용자의 기본 정보를 관리합니다.

<br>

#### 3. 전적 관련 필드 추가
``` sql
ALTER TABLE users
ADD wins INT DEFAULT 0,
ADD losses INT DEFAULT 0,
ADD ties INT DEFAULT 0;
```
사용자가 게임에서 승리, 패배, 무승부를 기록할 수 있도록 wins, losses, ties 필드를 추가하여 사용자 전적을 관리할 수 있게 했습니다.

<br>

#### 	4. 게임 기록 테이블 생성
``` sql
CREATE TABLE IF NOT EXISTS game_history (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '게임 기록 ID',
    player_id INT NOT NULL COMMENT '사용자 ID 번호',
    user_choice VARCHAR(50) NOT NULL COMMENT '사용자가 선택한 값',
    server_choice VARCHAR(50) NOT NULL COMMENT '서버가 선택한 값',
    result VARCHAR(50) NOT NULL COMMENT '결과 (win, lose, tie)',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '게임 실행 시간',
    FOREIGN KEY (player_id) REFERENCES users(player_id) ON DELETE CASCADE
);
```
game_history 테이블은 각 게임의 기록을 저장합니다. <br>
이 테이블에는 사용자 ID, 사용자의 선택, 서버의 선택, 게임 결과, 게임 실행 시간이 포함되어 사용자의 게임 기록을 추적할 수 있습니다. <br>
또한, player_id를 외래 키로 사용하여 users 테이블과 관계를 맺고, 사용자가 삭제될 경우 관련된 게임 기록도 함께 삭제되도록 설정했습니다. <br>

<br>

#### users 스크린샷
![스크린샷 2024-12-16 04 09 54](https://github.com/user-attachments/assets/bbd8d088-a859-423f-a5e1-44f9ca626939)

<br>

#### game_history 스크린샷
![스크린샷 2024-12-16 04 10 26](https://github.com/user-attachments/assets/5873f25c-a37d-4249-abce-c64fee7414f2)


<br>
<br>

### 서버
``` js
// server.js
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

    // 토큰 검증
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

    // 사용자 선택과 서버 선택 비교
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



// 서버 시작
app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});
```

```
// .env
ACCESS_TOKEN_SECRET=your-access-token-secret
REFRESH_TOKEN_SECRET=your-refresh-token-secret
DB_HOST='localhost'
DB_USER='root'
DB_PASSWORD='shingu'
DB_NAME='Game_DB_02'
```

#### 주요 기능
|기능|설명|
|-|-|
|1. 회원가입 및 로그인|비밀번호는 bcrypt로 해싱되어 데이터베이스에 저장되며, 로그인 후 액세스 토큰과 리프레시 토큰을 생성합니다.|
|2. JWT 토큰 인증|JWT를 사용하여 로그인한 사용자의 인증을 관리합니다. 리프레시 토큰은 httpOnly 쿠키로 저장되어 보안성을 강화합니다.|
|3.	게임 로직|가위바위보 게임을 구현하여 사용자가 선택한 값과 서버의 선택을 비교하고 결과를 기록합니다.|
|4. 게임 기록 저장| 게임 결과는 game_history 테이블에 저장되어 사용자가 자신의 게임 기록을 확인할 수 있습니다.|
|5.	랭킹 시스템|wins, losses, ties에 기반하여 사용자의 순위를 매깁니다.|

<br>

#### .env 파일 내용 설명
|기능|설명|
|-|-|
|1. ACCESS_TOKEN_SECRET|JWT 액세스 토큰을 안전하게 생성하고 검증하기 위해 필요한 비밀 키입니다.|
|2. REFRESH_TOKEN_SECRET|리프레시 토큰의 생성과 검증을 위한 비밀 키입니다.|
|3.	DB_HOST|데이터베이스 서버가 어디에 위치하는지 정의합니다.|
|4. DB_USER| MySQL 데이터베이스에 접근할 수 있는 사용자 계정을 지정합니다.|
|5.	DB_PASSWORD|데이터베이스 사용자 계정에 대한 인증을 위해 사용됩니다.|
|6.	DB_NAME|연결하려는 특정 데이터베이스를 지정합니다.|

<br>

#### 포스트맨 실험
##### 회원가입
![스크린샷 2024-12-16 04 14 03](https://github.com/user-attachments/assets/147506d2-e9ed-4e85-bdc6-110e4222047d)
![스크린샷 2024-12-16 04 15 49](https://github.com/user-attachments/assets/9ff6ae2d-ea02-471a-ac61-8b9a6c39c411)

<br>

##### 로그인
![스크린샷 2024-12-16 04 18 17](https://github.com/user-attachments/assets/49745e98-4d2d-416f-9148-6bfd64c57200)
![스크린샷 2024-12-16 04 18 44](https://github.com/user-attachments/assets/2b3726f3-44e8-4a3c-ae26-89a8a3e83caf)

<br>

##### 게임플레이
![스크린샷 2024-12-16 04 21 12](https://github.com/user-attachments/assets/9f17fa3d-8272-49a5-83ce-308e5e998a48)
![스크린샷 2024-12-16 04 22 07](https://github.com/user-attachments/assets/8e678bf4-87f6-44d9-a013-bb824ab53acb)
![스크린샷 2024-12-16 04 22 21](https://github.com/user-attachments/assets/57c4ddf2-cd4c-43ab-a584-5f5aabc9174e)



