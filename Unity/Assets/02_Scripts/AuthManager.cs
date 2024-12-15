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