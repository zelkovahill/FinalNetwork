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

<br>

##### 전적보기
![스크린샷 2024-12-16 04 24 23](https://github.com/user-attachments/assets/ed5f32ed-c46f-4c63-b21b-14b0a8b34e36)


<br>

##### 랭킹
![스크린샷 2024-12-16 04 25 50](https://github.com/user-attachments/assets/997a907c-059c-4526-ab94-0c4022b319cc)

<br>
<br>
<br>

### 유니티

#### 스크립트

##### AuthManager.cs
``` cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;
using System;
using System.Text;

// 인증 요청을 위한 클래스
public class AuthRequest
{
    public string username;  // 사용자 이름
    public string password;  // 사용자 비밀번호

    // 생성자
    public AuthRequest(string username, string password)
    {
        this.username = username;
        this.password = password;
    }
}

// 로그인 응답을 처리할 클래스
public class LoginResponse
{
    public string accessToken;  // 로그인 성공 시 반환되는 access token
    public string refreshToken; // 로그인 성공 시 반환되는 refresh token
}

// refresh token을 사용하여 새로운 access token을 요청하는 응답 클래스
[System.Serializable]
public class RefreshTokenResponse
{
    public string accessToken;  // 새로 발급된 access token
}

// refresh token 요청을 위한 클래스
[System.Serializable]
public class RefreshTokenRequest
{
    public string refreshToken;  // refresh token

    // 생성자
    public RefreshTokenRequest(string refreshToken)
    {
        this.refreshToken = refreshToken;
    }
}

// 인증 관련 처리를 담당하는 클래스
public class AuthManager : MonoBehaviour
{
    // 서버 URL 및 PlayerPrefs에 저장할 키값 정의
    private const string SERVER_URL = "http://localhost:3000";
    private const string ACCESS_TOKEN_PREFS_KET = "AccessToken";
    private const string REFRESH_TOKEN_PREFS_KEY = "RefreshToken";
    private const string TOKEN_EXPIRY_PREFS_KEY = "TokenExpiry";

    // 토큰 및 만료 시간 저장 변수
    private string accessToken;
    private string refreshToken;
    private DateTime tokenExpiryTime;

    // 초기화 시 토큰을 PlayerPrefs에서 불러옴
    private void Start()
    {
        LoadTokenFromPrefs();
    }

    // PlayerPrefs에서 저장된 토큰을 불러오는 함수
    private void LoadTokenFromPrefs()
    {
        accessToken = PlayerPrefs.GetString(ACCESS_TOKEN_PREFS_KET);
        refreshToken = PlayerPrefs.GetString(REFRESH_TOKEN_PREFS_KEY);

        long expiryTicks = Convert.ToInt64(PlayerPrefs.GetString(TOKEN_EXPIRY_PREFS_KEY, "0"));
        tokenExpiryTime = new DateTime(expiryTicks);
    }

    // 토큰을 PlayerPrefs에 저장하는 함수
    private void SaveTokenToPrefs(string accessToken, string refreshToken, DateTime expiryTime)
    {
        PlayerPrefs.SetString(ACCESS_TOKEN_PREFS_KET, accessToken);
        PlayerPrefs.SetString(REFRESH_TOKEN_PREFS_KEY, refreshToken);
        PlayerPrefs.SetString(TOKEN_EXPIRY_PREFS_KEY, expiryTime.Ticks.ToString());
        PlayerPrefs.Save();

        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenExpiryTime = expiryTime;
    }

    // 회원가입 요청을 보내는 코루틴
    public IEnumerator Register(string username, string password)
    {
        // 요청 데이터 생성
        AuthRequest request = new AuthRequest(username, password);
        var jsonData = JsonUtility.ToJson(request);

        using (UnityWebRequest www = UnityWebRequest.PostWwwForm($"{SERVER_URL}/register", "POST"))
        {
            byte[] bodyRaw = Encoding.UTF8.GetBytes(jsonData);  // JSON 데이터를 바이트 배열로 변환
            www.uploadHandler = new UploadHandlerRaw(bodyRaw);
            www.downloadHandler = new DownloadHandlerBuffer();
            www.SetRequestHeader("Content-Type", "application/json");

            yield return www.SendWebRequest();  // 서버 요청 보내기

            // 서버 응답 처리
            if (www.result != UnityWebRequest.Result.Success)
            {
                Debug.Log($"Registeration Error : {www.error}");
            }
            else
            {
                Debug.Log("Registeration successful");
            }
        }
    }

    // 로그인 요청을 보내는 코루틴
    public IEnumerator Login(string username, string password)
    {
        AuthRequest request = new AuthRequest(username, password);
        var jsonData = JsonUtility.ToJson(request);

        using (UnityWebRequest www = new UnityWebRequest($"{SERVER_URL}/login", "POST"))
        {
            byte[] bodyRaw = Encoding.UTF8.GetBytes(jsonData);  // JSON 데이터를 바이트 배열로 변환
            www.uploadHandler = new UploadHandlerRaw(bodyRaw);
            www.downloadHandler = new DownloadHandlerBuffer();
            www.SetRequestHeader("Content-Type", "application/json");

            yield return www.SendWebRequest();  // 서버 요청 보내기

            // 서버 응답 처리
            if (www.result != UnityWebRequest.Result.Success)
            {
                Debug.Log($"Login Error : {www.error}");
            }
            else
            {
                // 로그인 성공 시 accessToken과 refreshToken을 저장
                var response = JsonUtility.FromJson<LoginResponse>(www.downloadHandler.text);
                SaveTokenToPrefs(response.accessToken, response.refreshToken, DateTime.UtcNow.AddMinutes(15));

                Debug.Log("Login successful");
            }
        }
    }

    // 로그아웃 요청을 보내는 코루틴
    public IEnumerator Logout()
    {
        var logoutData = new { refreshToken };
        var jsonData = JsonUtility.ToJson(logoutData);

        using (UnityWebRequest www = UnityWebRequest.PostWwwForm($"{SERVER_URL}/logout", "POST"))
        {
            byte[] bodyRaw = Encoding.UTF8.GetBytes(jsonData);  // JSON 데이터를 바이트 배열로 변환
            www.uploadHandler = new UploadHandlerRaw(bodyRaw);
            www.downloadHandler = new DownloadHandlerBuffer();
            www.SetRequestHeader("Content-Type", "application/json");

            yield return www.SendWebRequest();  // 서버 요청 보내기

            // 서버 응답 처리
            if (www.result != UnityWebRequest.Result.Success)
            {
                Debug.Log($"Logout Error : {www.error}");
            }
            else
            {
                // 로그아웃 성공 시 토큰 정보 삭제
                accessToken = "";
                refreshToken = "";
                tokenExpiryTime = DateTime.MinValue;
                PlayerPrefs.DeleteKey(ACCESS_TOKEN_PREFS_KET);
                PlayerPrefs.DeleteKey(REFRESH_TOKEN_PREFS_KEY);
                PlayerPrefs.DeleteKey(TOKEN_EXPIRY_PREFS_KEY);
                PlayerPrefs.Save();

                Debug.Log("Logout successful");
            }
        }
    }

    // refresh token을 사용해 access token을 갱신하는 코루틴
    public IEnumerator RefreshToken()
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            Debug.Log("리프레시 토큰이 없습니다.");
            yield break;
        }

        var refreshData = new RefreshTokenRequest(refreshToken);
        var jsonData = JsonUtility.ToJson(refreshData);

        using (UnityWebRequest www = UnityWebRequest.PostWwwForm($"{SERVER_URL}/token", "POST"))
        {
            byte[] bodyRaw = Encoding.UTF8.GetBytes(jsonData);  // JSON 데이터를 바이트 배열로 변환
            www.uploadHandler = new UploadHandlerRaw(bodyRaw);
            www.downloadHandler = new DownloadHandlerBuffer();
            www.SetRequestHeader("Content-Type", "application/json");

            yield return www.SendWebRequest();  // 서버 요청 보내기

            // 서버 응답 처리
            if (www.result != UnityWebRequest.Result.Success)
            {
                Debug.Log($"Token Refresh Error : {www.error}");
                yield return Login("username", "password"); // 로그인 시도 (실제로는 저장된 사용자 정보 사용)
            }
            else
            {
                // 갱신된 accessToken 저장
                var response = JsonUtility.FromJson<RefreshTokenResponse>(www.downloadHandler.text);
                SaveTokenToPrefs(response.accessToken, refreshToken, DateTime.UtcNow.AddMinutes(15));
                Debug.Log("Token refreshed successfully");
            }
        }
    }

    // 보호된 데이터 요청을 보내는 코루틴
    public IEnumerator GetProtectedData()
    {
        // 토큰이 없거나 만료된 경우 토큰 갱신 시도
        if (string.IsNullOrEmpty(accessToken) || DateTime.UtcNow >= tokenExpiryTime)
        {
            Debug.Log("토큰이 만료되었습니다. 토큰 갱신 시도");
            yield return RefreshToken();  // 토큰 갱신 시도
        }

        // 보호된 데이터 요청 보내기
        using (UnityWebRequest www = UnityWebRequest.Get($"{SERVER_URL}/protected"))
        {
            www.SetRequestHeader("Authorization", $"Bearer {accessToken}");

            yield return www.SendWebRequest();  // 서버 요청 보내기

            // 서버 응답 처리
            if (www.result != UnityWebRequest.Result.Success)
            {
                Debug.Log($"GetProtectedData Error : {www.error}");
            }
            else
            {
                Debug.Log($"Protected Data : {www.downloadHandler.text}");
            }
        }
    }
}
```

<br>

##### AuthUI
``` cs
using System.Collections;
using System.Collections.Generic;
using TMPro; // TextMeshPro를 사용하기 위한 네임스페이스
using UnityEngine;
using UnityEngine.UI; // UI 컨트롤을 위한 네임스페이스

// AuthUI 클래스는 사용자 인터페이스(UI)를 처리하고 AuthManager와 상호작용하는 역할을 합니다.
public class AuthUI : MonoBehaviour
{
    [Header("#1 인풋 UI")]
    // 사용자 이름과 비밀번호를 입력받는 필드
    public TMP_InputField usernameInput;
    public TMP_InputField passwordInput;

    [Header("#2 버튼 UI")]
    // 회원가입, 로그인, 로그아웃, 데이터 요청 버튼
    public Button registerButton;
    public Button loginButton;
    public Button logoutButton;
    public Button getDataButton;

    // 인증 관련 작업을 수행하는 AuthManager의 참조
    private AuthManager authManager;

    // Start 메서드: UI 초기화 및 버튼 클릭 이벤트 연결
    private void Start()
    {
        // 동일한 게임 오브젝트에 있는 AuthManager 컴포넌트 가져오기
        authManager = GetComponent<AuthManager>();

        // 버튼 클릭 이벤트에 핸들러 메서드 연결
        registerButton.onClick.AddListener(OnResisterClick);
        loginButton.onClick.AddListener(OnLoginClick);
        logoutButton.onClick.AddListener(OnLogoutClick);
        getDataButton.onClick.AddListener(OnGetDataClick);
    }

    // 회원가입 버튼 클릭 이벤트 핸들러
    private void OnResisterClick() => StartCoroutine(RegisterCorutine());
    
    // 로그인 버튼 클릭 이벤트 핸들러
    private void OnLoginClick() => StartCoroutine(LoginCorutine());
    
    // 로그아웃 버튼 클릭 이벤트 핸들러
    private void OnLogoutClick() => StartCoroutine(LogoutCorutine());
    
    // 보호된 데이터 요청 버튼 클릭 이벤트 핸들러
    private void OnGetDataClick() => StartCoroutine(GetDataCorutine());

    // 회원가입 코루틴: 입력된 사용자 이름과 비밀번호를 AuthManager의 Register 메서드로 전달
    private IEnumerator RegisterCorutine()
    {
        yield return authManager.Register(usernameInput.text, passwordInput.text);
    }

    // 로그인 코루틴: 입력된 사용자 이름과 비밀번호를 AuthManager의 Login 메서드로 전달
    private IEnumerator LoginCorutine()
    {
        yield return authManager.Login(usernameInput.text, passwordInput.text);
    }

    // 로그아웃 코루틴: AuthManager의 Logout 메서드 호출
    private IEnumerator LogoutCorutine()
    {
        yield return authManager.Logout();
    }

    // 보호된 데이터 요청 코루틴: AuthManager의 GetProtectedData 메서드 호출
    private IEnumerator GetDataCorutine()
    {
        yield return StartCoroutine(authManager.GetProtectedData());
    }
}
```

<br>

##### GameManager.cs
``` cs
using System.Collections;
using UnityEngine.Networking; // Unity의 네트워크 요청을 처리하기 위한 네임스페이스
using UnityEngine;

// 서버 응답으로 전달되는 게임 결과 데이터를 표현하는 클래스
[System.Serializable]
public class GameResult
{
    public string result;       // 게임 결과 (예: "win", "lose", "draw")
    public string serverChoice; // 서버가 선택한 가위바위보 값 (예: "scissors")
}

// 클라이언트에서 서버로 보낼 데이터 구조를 나타내는 클래스
[System.Serializable]
public class ChoiceData
{
    public string choice;       // 플레이어가 선택한 가위바위보 값 (예: "rock", "paper", "scissors")
}

// 새로고침 토큰 데이터를 저장하기 위한 클래스
[System.Serializable]
public class RefreshTokenData
{
    public string refreshToken; // 서버에서 발급된 리프레시 토큰
}

// GameManager 클래스는 게임 로직 및 서버와의 네트워크 통신을 관리합니다.
public class GameManager : MonoBehaviour
{
    private const string SERVER_URL = "http://localhost:3000/play"; // 서버의 게임 API URL

    // 플레이어의 선택을 서버로 보내고 응답을 처리하는 코루틴
    public IEnumerator PostPlayGame(string choice)
    {
        // 서버로 보낼 데이터 생성
        ChoiceData jsonData = new ChoiceData { choice = choice };

        // 데이터를 JSON 형식으로 변환
        string json = JsonUtility.ToJson(jsonData);

        // HTTP POST 요청 생성
        using (UnityWebRequest www = UnityWebRequest.PostWwwForm(SERVER_URL, "POST"))
        {
            // 요청 헤더에 JWT 토큰 추가
            www.SetRequestHeader("Authorization", "Bearer " + PlayerPrefs.GetString("AccessToken"));
            www.SetRequestHeader("Content-Type", "application/json");

            // 요청 본문에 JSON 데이터 추가
            byte[] jsonToSend = new System.Text.UTF8Encoding().GetBytes(json);
            www.uploadHandler = new UploadHandlerRaw(jsonToSend); // JSON 데이터를 전송용으로 설정
            www.downloadHandler = new DownloadHandlerBuffer();    // 응답 데이터를 받을 버퍼 설정

            // 서버로 요청 전송
            yield return www.SendWebRequest();

            // 요청 성공 여부 확인
            if (www.result == UnityWebRequest.Result.Success)
            {
                // 서버로부터의 응답 처리
                string responseText = www.downloadHandler.text;
                Debug.Log("Response: " + responseText);

                // 응답 데이터를 바탕으로 게임 결과 처리
                ProcessGameResult(responseText);
            }
            else
            {
                // 요청 실패 시 에러 메시지 출력
                Debug.Log("Error: " + www.error);
            }
        }
    }

    // 서버에서 받은 게임 결과를 처리하는 메서드
    private void ProcessGameResult(string responseText)
    {
        // 서버 응답 JSON 데이터를 GameResult 객체로 변환
        var resultData = JsonUtility.FromJson<GameResult>(responseText);

        // 서버에서 받은 게임 결과와 서버의 선택 출력
        Debug.Log("Game Result: " + resultData.result);         // 예: "win"
        Debug.Log("Server Choice: " + resultData.serverChoice); // 예: "scissors"

        // 추가적으로 UI 업데이트나 게임 로직 처리 가능
    }
}
```

##### GameUI.cs
``` cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using TMPro;
using UnityEngine.UI;

// GameUI 클래스는 UI 요소와 게임 로직 간의 상호작용을 관리합니다.
public class GameUI : MonoBehaviour
{
    [Header("#1 가위바위보 버튼 UI")]
    public Button rockButton;       // '바위' 버튼
    public Button paperButton;      // '보' 버튼
    public Button scissorsButton;   // '가위' 버튼

    [Header("#2 게임 결과 UI")]
    public TextMeshProUGUI resultText;        // 게임 결과를 표시하는 텍스트
    public TextMeshProUGUI serverChoiceText;  // 서버의 선택을 표시하는 텍스트
    public TextMeshProUGUI userChoiceText;    // 플레이어의 선택을 표시하는 텍스트

    [Header("#3 게임 매니저 및 랭킹 시스템")]
    public Button HistoryButton;    // 게임 히스토리 버튼
    public Button RankingButton;    // 랭킹 버튼

    // 게임과 관련된 매니저 클래스 참조
    private GameManager gameManager;               // 게임 로직을 처리하는 매니저
    private GameHistoryManager gameHistoryManager; // 게임 히스토리 데이터를 관리하는 매니저
    private RankingSystem rankingSystem;           // 랭킹 시스템을 관리하는 매니저

    // 게임 시작 시 초기화
    private void Start()
    {
        // 게임 매니저 및 관련 컴포넌트 초기화
        gameManager = GetComponent<GameManager>();
        gameHistoryManager = GetComponent<GameHistoryManager>();
        rankingSystem = GetComponent<RankingSystem>();

        // 버튼 클릭 이벤트에 리스너 등록
        rockButton.onClick.AddListener(() => OnRockButtonClick());
        paperButton.onClick.AddListener(() => OnPaperButtonClick());
        scissorsButton.onClick.AddListener(() => OnScissorsButtonClick());
        HistoryButton.onClick.AddListener(() => OnHistoryButtonClick());
        RankingButton.onClick.AddListener(() => OnRankingButtonClick());
    }

    // '바위' 버튼 클릭 시 호출
    private void OnRockButtonClick() => StartCoroutine(PlayGameCoroutine("rock"));

    // '보' 버튼 클릭 시 호출
    private void OnPaperButtonClick() => StartCoroutine(PlayGameCoroutine("paper"));

    // '가위' 버튼 클릭 시 호출
    private void OnScissorsButtonClick() => StartCoroutine(PlayGameCoroutine("scissors"));

    // 히스토리 버튼 클릭 시 호출
    private void OnHistoryButtonClick() => StartCoroutine(GetHistoryCoroutine());

    // 랭킹 버튼 클릭 시 호출
    private void OnRankingButtonClick() => StartCoroutine(GetRankingCoroutine());

    // 선택한 가위바위보를 서버에 전송하고 결과를 처리하는 코루틴
    private IEnumerator PlayGameCoroutine(string choice)
    {
        yield return gameManager.PostPlayGame(choice); // 선택한 데이터를 서버로 전송
    }

    // 게임 히스토리를 서버에서 가져오는 코루틴
    private IEnumerator GetHistoryCoroutine()
    {
        yield return gameHistoryManager.GetHistory(); // 히스토리 데이터 요청
    }

    // 랭킹 데이터를 서버에서 가져오는 코루틴
    private IEnumerator GetRankingCoroutine()
    {
        yield return rankingSystem.FetchRanking(); // 랭킹 데이터 요청
    }
}
```

<br>

##### GameHistoryManager.cs

``` cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;

// 서버에서 반환된 게임 히스토리 데이터 구조
[System.Serializable]
public class GameHistoryResponse
{
    public List<GameHistory> history; // 게임 히스토리의 리스트
}

// 개별 게임 히스토리 데이터 구조
[System.Serializable]
public class GameHistory
{
    public string user_choice;   // 사용자가 선택한 옵션 (가위, 바위, 보)
    public string server_choice; // 서버가 선택한 옵션
    public string result;        // 게임 결과 (승리, 패배, 무승부 등)
    public string timestamp;     // 게임이 진행된 시간
}

// GameHistoryManager 클래스는 서버와 통신하여 게임 히스토리를 관리합니다.
public class GameHistoryManager : MonoBehaviour
{
    private const string SERVER_URL = "http://localhost:3000/history"; // 히스토리 API의 엔드포인트 URL

    // 서버에서 게임 히스토리 데이터를 가져오는 메서드
    public IEnumerator GetHistory()
    {
        // UnityWebRequest를 사용해 서버에 GET 요청
        using (UnityWebRequest www = UnityWebRequest.Get(SERVER_URL))
        {
            // 요청 헤더에 인증 토큰 추가
            www.SetRequestHeader("Authorization", "Bearer " + PlayerPrefs.GetString("AccessToken"));

            // 서버로 요청을 보냄
            yield return www.SendWebRequest();

            // 요청 결과 처리
            if (www.result == UnityWebRequest.Result.Success)
            {
                // 서버 응답을 텍스트로 가져옴
                string responseText = www.downloadHandler.text;
                Debug.Log("History: " + responseText);

                // 히스토리 데이터 처리
                ProcessGameHistory(responseText);
            }
            else
            {
                // 요청 실패 시 오류 로그 출력
                Debug.Log("Error: " + www.error);
            }
        }
    }

    // 서버에서 받은 게임 히스토리 데이터를 처리하는 메서드
    private void ProcessGameHistory(string responseText)
    {
        // JSON 데이터를 GameHistoryResponse 객체로 변환
        var historyData = JsonUtility.FromJson<GameHistoryResponse>(responseText);

        // 각 게임 기록 출력
        foreach (var game in historyData.history)
        {
            Debug.Log($"Choice: {game.user_choice}, Server: {game.server_choice}, Result: {game.result}, Time: {game.timestamp}");
        }
    }
}
```

<br>

##### RankingSystem.cs
``` cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;

// RankingSystem 클래스는 서버에서 랭킹 데이터를 가져와 처리하는 역할을 합니다.
public class RankingSystem : MonoBehaviour
{
    private const string SERVER_URL = "http://localhost:3000/ranking"; // 랭킹 API의 엔드포인트 URL

    // 서버에서 랭킹 데이터를 가져오는 코루틴
    public IEnumerator FetchRanking()
    {
        // UnityWebRequest를 사용하여 서버에 GET 요청을 보냄
        UnityWebRequest request = UnityWebRequest.Get(SERVER_URL);

        // 요청이 완료될 때까지 대기
        yield return request.SendWebRequest();

        // 요청 결과 처리
        if (request.result == UnityWebRequest.Result.Success)
        {
            // 요청 성공 시 서버 응답 데이터를 문자열로 가져옴
            string rankingData = request.downloadHandler.text;
            Debug.Log("Ranking Data: " + rankingData);

            // 받은 랭킹 데이터를 UI에 표시하거나 추가 작업 수행
            // 랭킹 데이터를 JSON으로 파싱한 후 사용 가능
        }
        else
        {
            // 요청 실패 시 오류 로그 출력
            Debug.LogError("Failed to fetch ranking: " + request.error);
        }
    }
}
```
