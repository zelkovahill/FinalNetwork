using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;

[System.Serializable]
public class GameHistoryResponse
{
    public List<GameHistory> history;
}

[System.Serializable]
public class GameHistory
{
    public string user_choice;
    public string server_choice;
    public string result;
    public string timestamp;
}

public class GameHistoryManager : MonoBehaviour
{
    private const string SERVER_URL = "http://localhost:3000/history";

    public IEnumerator GetHistory()
    {
        using (UnityWebRequest www = UnityWebRequest.Get(SERVER_URL))
        {

            www.SetRequestHeader("Authorization", "Bearer " + PlayerPrefs.GetString("AccessToken"));

            yield return www.SendWebRequest();

            if (www.result == UnityWebRequest.Result.Success)
            {
                string responseText = www.downloadHandler.text;
                Debug.Log("History: " + responseText);

                // 결과 출력
                ProcessGameHistory(responseText);
            }
            else
            {
                Debug.Log("Error: " + www.error);
            }
        }
    }

    // 게임 히스토리 처리
    private void ProcessGameHistory(string responseText)
    {
        var historyData = JsonUtility.FromJson<GameHistoryResponse>(responseText);

        foreach (var game in historyData.history)
        {
            Debug.Log($"Choice: {game.user_choice}, Server: {game.server_choice}, Result: {game.result}, Time: {game.timestamp}");
        }
    }

}
