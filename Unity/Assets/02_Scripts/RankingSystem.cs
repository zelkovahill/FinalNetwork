using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;

public class RankingSystem : MonoBehaviour
{
    private const string SERVER_URL = "http://localhost:3000/ranking";


    public IEnumerator FetchRanking()
    {
        UnityWebRequest request = UnityWebRequest.Get(SERVER_URL);
        yield return request.SendWebRequest();

        if (request.result == UnityWebRequest.Result.Success)
        {
            // 서버에서 받은 랭킹 데이터를 처리
            string rankingData = request.downloadHandler.text;
            Debug.Log("Ranking Data: " + rankingData);
            // 랭킹 데이터를 파싱해서 UI에 표시하거나 다른 작업 수행
        }
        else
        {
            Debug.LogError("Failed to fetch ranking: " + request.error);
        }
    }
}
