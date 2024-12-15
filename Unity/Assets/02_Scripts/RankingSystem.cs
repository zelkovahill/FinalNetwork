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