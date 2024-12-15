using System.Collections;
using UnityEngine.Networking;
using UnityEngine;

[System.Serializable]
public class GameResult
{
    public string result;
    public string serverChoice;
}

[System.Serializable]
public class ChoiceData
{
    public string choice;
}

[System.Serializable]
public class RefreshTokenData
{
    public string refreshToken;  // 서버에서 받은 refresh token
}

public class GameManager : MonoBehaviour
{
    private const string SERVER_URL = "http://localhost:3000/play";

    // 가위바위보 게임 플레이
    public IEnumerator PostPlayGame(string choice)
    {
        ChoiceData jsonData = new ChoiceData { choice = choice };

        string json = JsonUtility.ToJson(jsonData);

        using (UnityWebRequest www = UnityWebRequest.PostWwwForm(SERVER_URL, "POST"))
        {
            // 요청 헤더에 인증 토큰 추가 (JWT)
            www.SetRequestHeader("Authorization", "Bearer " + PlayerPrefs.GetString("AccessToken"));
            www.SetRequestHeader("Content-Type", "application/json");

            // 요청 본문에 JSON 데이터 넣기
            byte[] jsonToSend = new System.Text.UTF8Encoding().GetBytes(json);

            string jsonToSendString = System.Text.Encoding.UTF8.GetString(jsonToSend);

            www.uploadHandler = new UploadHandlerRaw(jsonToSend);
            www.downloadHandler = new DownloadHandlerBuffer();

            // 요청 전송
            yield return www.SendWebRequest();

            if (www.result == UnityWebRequest.Result.Success)
            {
                // 서버 응답 처리
                string responseText = www.downloadHandler.text;
                Debug.Log("Response: " + responseText);

                // 결과 출력
                ProcessGameResult(responseText);
            }
            else
            {
                Debug.Log("Error: " + www.error);
            }
        }
    }

    // 게임 결과 처리 (예: UI 업데이트)
    private void ProcessGameResult(string responseText)
    {
        // 서버 응답 예시: {"result": "win", "serverChoice": "scissors"}
        var resultData = JsonUtility.FromJson<GameResult>(responseText);

        // 결과 출력 (UI나 로그)
        Debug.Log("Game Result: " + resultData.result);
        Debug.Log("Server Choice: " + resultData.serverChoice);

        // UI 업데이트 또는 게임 로직 구현 가능
    }

}
