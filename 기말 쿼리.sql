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

