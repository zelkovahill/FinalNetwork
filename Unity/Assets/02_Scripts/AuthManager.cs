using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;
using System;
using System.Text;


public class AuthRequest
{
    public string username;
    public string password;

    public AuthRequest(string username, string password)
    {
        this.username = username;
        this.password = password;
    }
}

public class LoginResponse
{
    public string accessToken;
    public string refreshToken;
}

[System.Serializable]
public class RefreshTokenResponse
{
    public string accessToken;
}

[System.Serializable]
public class RefreshTokenRequest
{
    public string refreshToken;

    public RefreshTokenRequest(string refreshToken)
    {
        this.refreshToken = refreshToken;
    }
}

public class AuthManager : MonoBehaviour
{
    // 서버 URL 및 PlayerPrefs 키값 정의
    private const string SERVER_URL = "http://localhost:3000";
    private const string ACCESS_TOKEN_PREFS_KET = "AccessToken";
    private const string REFRESH_TOKEN_PREFS_KEY = "RefreshToken";
    private const string TOKEN_EXPIRY_PREFS_KEY = "TokenExpiry";

    // 토큰 및 만료 시간 저장 변수
    private string accessToken;
    private string refreshToken;
    private DateTime tokenExpiryTime;

    private void Start()
    {
        LoadTokenFromPrefs();
    }

    private void LoadTokenFromPrefs()
    {
        accessToken = PlayerPrefs.GetString(ACCESS_TOKEN_PREFS_KET);
        refreshToken = PlayerPrefs.GetString(REFRESH_TOKEN_PREFS_KEY);

        long expiryTicks = Convert.ToInt64(PlayerPrefs.GetString(TOKEN_EXPIRY_PREFS_KEY, "0"));
        tokenExpiryTime = new DateTime(expiryTicks);
    }

    // PlayerPrefs에 토큰 정보 저장
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


    // 회원 가입 코루틴
    public IEnumerator Register(string username, string password)
    {
        AuthRequest request = new AuthRequest(username, password);
        var jsonData = JsonUtility.ToJson(request);

        using (UnityWebRequest www = UnityWebRequest.PostWwwForm($"{SERVER_URL}/register", "POST"))
        {
            byte[] bodyRaw = Encoding.UTF8.GetBytes(jsonData);
            www.uploadHandler = new UploadHandlerRaw(bodyRaw);
            www.downloadHandler = new DownloadHandlerBuffer();
            www.SetRequestHeader("Content-Type", "application/json");

            yield return www.SendWebRequest();

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

    // 로그인 코루틴
    public IEnumerator Login(string username, string password)
    {
        // var user = new { username, password };
        AuthRequest request = new AuthRequest(username, password);
        var jsonData = JsonUtility.ToJson(request);

        using (UnityWebRequest www = new UnityWebRequest($"{SERVER_URL}/login", "POST"))
        {
            byte[] bodyRaw = Encoding.UTF8.GetBytes(jsonData);
            www.uploadHandler = new UploadHandlerRaw(bodyRaw);
            www.downloadHandler = new DownloadHandlerBuffer();
            www.SetRequestHeader("Content-Type", "application/json");

            yield return www.SendWebRequest();

            if (www.result != UnityWebRequest.Result.Success)
            {
                Debug.Log($"Login Error : {www.error}");
            }
            else
            {
                var respone = JsonUtility.FromJson<LoginResponse>(www.downloadHandler.text);
                SaveTokenToPrefs(respone.accessToken, respone.refreshToken, DateTime.UtcNow.AddMinutes(15));

                Debug.Log("Login successful");

            }
        }
    }

    // 로그아웃 코루틴
    public IEnumerator Logout()
    {
        var logoutData = new { refreshToken };
        var jsonData = JsonUtility.ToJson(logoutData);

        using (UnityWebRequest www = UnityWebRequest.PostWwwForm($"{SERVER_URL}/logout", "POST"))
        {
            byte[] bodyRaw = Encoding.UTF8.GetBytes(jsonData);
            www.uploadHandler = new UploadHandlerRaw(bodyRaw);
            www.downloadHandler = new DownloadHandlerBuffer();
            www.SetRequestHeader("Content-Type", "application/json");

            yield return www.SendWebRequest();

            if (www.result != UnityWebRequest.Result.Success)
            {
                Debug.Log($"Logout Error : {www.error}");
            }
            else
            {
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

    // 토큰 갱신 코루틴
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
            byte[] bodyRaw = Encoding.UTF8.GetBytes(jsonData);
            www.uploadHandler = new UploadHandlerRaw(bodyRaw);
            www.downloadHandler = new DownloadHandlerBuffer();
            www.SetRequestHeader("Content-Type", "application/json");

            yield return www.SendWebRequest();


            if (www.result != UnityWebRequest.Result.Success)
            {
                Debug.Log($"Registeration Error : {www.error}");
                yield return Login("username", "password"); // 실구현에서는 저장된 사용자 정보를 사용
            }
            else
            {
                var response = JsonUtility.FromJson<RefreshTokenResponse>(www.downloadHandler.text);
                SaveTokenToPrefs(response.accessToken, refreshToken, DateTime.UtcNow.AddMinutes(15));
                Debug.Log("Token refreshed successfully");
            }
        }
    }

    // 보호된 데이터 가져오기 코루틴
    public IEnumerator GetProtectedData()
    {
        if (string.IsNullOrEmpty(accessToken) || DateTime.UtcNow >= tokenExpiryTime)
        {
            Debug.Log("토큰이 만료되었습니다. 토큰 갱신 시도");
        }

        using (UnityWebRequest www = UnityWebRequest.Get($"{SERVER_URL}/protected"))
        {
            www.SetRequestHeader("Authorization", $"Bearer {accessToken}");

            yield return www.SendWebRequest();

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

