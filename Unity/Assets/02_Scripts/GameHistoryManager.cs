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